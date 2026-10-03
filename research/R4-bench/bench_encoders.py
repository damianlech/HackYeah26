"""Synthetic CPU latency benchmark for encoder-classifier architectures.

Builds random-weight BERT/DeBERTa-like encoders as ONNX graphs (no HF download needed),
then times onnxruntime CPU inference for batch=1 at several sequence lengths, FP32 and
dynamic INT8. Weights are random, so only latency (not accuracy) is meaningful.

Usage: pip install onnxruntime onnx numpy && SEQS=64,200,512 THREADS=4,1 python bench_encoders.py
(Needs ~2.5 GB free disk for the temporary models/ dir.)
"""
import time, sys, os
import numpy as np
import onnx
from onnx import helper, TensorProto, numpy_helper
import onnxruntime as ort
from onnxruntime.quantization import quantize_dynamic, QuantType

rng = np.random.default_rng(0)
OPSET = 20


def W(name, shape, inits):
    arr = (rng.standard_normal(shape) * 0.02).astype(np.float32)
    inits.append(numpy_helper.from_array(arr, name))
    return name


def build(cfg, path):
    L, H, A, I, V = cfg["layers"], cfg["hidden"], cfg["heads"], cfg["inter"], cfg["vocab"]
    rel = cfg.get("rel", 0)  # DeBERTa relative-position buckets*2 (0 = plain BERT)
    hd = H // A
    nodes, inits = [], []
    inp = helper.make_tensor_value_info("input_ids", TensorProto.INT64, [1, "S"])
    out = helper.make_tensor_value_info("logits", TensorProto.FLOAT, [1, 2])
    c = lambda n, v, dt=np.int64: inits.append(numpy_helper.from_array(np.array(v, dtype=dt), n)) or n
    c("shape_split", [1, -1, A, hd]); c("shape_merge", [1, -1, H]); c("scale", np.float32(1.0 / np.sqrt(hd)), np.float32)
    emb = W("tok_emb", [V, H], inits)
    nodes.append(helper.make_node("Gather", [emb, "input_ids"], ["x0"]))
    W("ln_e_g", [H], inits); W("ln_e_b", [H], inits)
    nodes.append(helper.make_node("LayerNormalization", ["x0", "ln_e_g", "ln_e_b"], ["h0"], axis=-1))
    if rel:
        W("rel_emb", [rel, H], inits)
    x = "h0"
    for l in range(L):
        p = f"l{l}_"
        def lin(inp_, din, dout, nm):
            w = W(p + nm + "_w", [din, dout], inits); b = W(p + nm + "_b", [dout], inits)
            nodes.append(helper.make_node("MatMul", [inp_, w], [p + nm + "_mm"]))
            nodes.append(helper.make_node("Add", [p + nm + "_mm", b], [p + nm]))
            return p + nm
        def heads(t):
            nodes.append(helper.make_node("Reshape", [t, "shape_split"], [t + "_r"]))
            nodes.append(helper.make_node("Transpose", [t + "_r"], [t + "_t"], perm=[0, 2, 1, 3]))
            return t + "_t"
        q, k, v = heads(lin(x, H, H, "q")), heads(lin(x, H, H, "k")), heads(lin(x, H, H, "v"))
        nodes.append(helper.make_node("Transpose", [k], [p + "kT"], perm=[0, 1, 3, 2]))
        nodes.append(helper.make_node("MatMul", [q, p + "kT"], [p + "s0"]))
        s = p + "s0"
        if rel:
            # emulate DeBERTa disentangled attention cost: project rel embeddings, then c2p and p2c score matmuls
            pk = lin("rel_emb", H, H, "relk"); pq = lin("rel_emb", H, H, "relq")
            for nm, a_, b_ in (("c2p", q, pk), ("p2c", k, pq)):
                nodes.append(helper.make_node("Reshape", [b_, "shape_split"], [p + nm + "_br"]))
                nodes.append(helper.make_node("Transpose", [p + nm + "_br"], [p + nm + "_bt"], perm=[0, 2, 3, 1]))
                nodes.append(helper.make_node("MatMul", [a_, p + nm + "_bt"], [p + nm + "_sc"]))  # [1,A,S,rel]
                # cheap reduction just keeps the c2p/p2c matmul in the graph (cost emulation, not exact math)
                nodes.append(helper.make_node("ReduceMean", [p + nm + "_sc"], [p + nm + "_red"], keepdims=1))
                nodes.append(helper.make_node("Add", [s, p + nm + "_red"], [p + nm + "_s"]))
                s = p + nm + "_s"
        nodes.append(helper.make_node("Mul", [s, "scale"], [p + "ss"]))
        nodes.append(helper.make_node("Softmax", [p + "ss"], [p + "pr"], axis=-1))
        nodes.append(helper.make_node("MatMul", [p + "pr", v], [p + "ctx"]))
        nodes.append(helper.make_node("Transpose", [p + "ctx"], [p + "ctx_t"], perm=[0, 2, 1, 3]))
        nodes.append(helper.make_node("Reshape", [p + "ctx_t", "shape_merge"], [p + "ctx_m"]))
        o = lin(p + "ctx_m", H, H, "o")
        nodes.append(helper.make_node("Add", [o, x], [p + "res1"]))
        W(p + "ln1_g", [H], inits); W(p + "ln1_b", [H], inits)
        nodes.append(helper.make_node("LayerNormalization", [p + "res1", p + "ln1_g", p + "ln1_b"], [p + "h1"], axis=-1))
        f1 = lin(p + "h1", H, I, "f1")
        nodes.append(helper.make_node("Gelu", [f1], [p + "g"]))
        f2 = lin(p + "g", I, H, "f2")
        nodes.append(helper.make_node("Add", [f2, p + "h1"], [p + "res2"]))
        W(p + "ln2_g", [H], inits); W(p + "ln2_b", [H], inits)
        nodes.append(helper.make_node("LayerNormalization", [p + "res2", p + "ln2_g", p + "ln2_b"], [p + "out"], axis=-1))
        x = p + "out"
    nodes.append(helper.make_node("Gather", [x, c("zero", 0)], ["pooled"], axis=1))  # [CLS] pooling
    W("cls_w", [H, 2], inits); W("cls_b", [2], inits)
    nodes.append(helper.make_node("MatMul", ["pooled", "cls_w"], ["cls_mm"]))
    nodes.append(helper.make_node("Add", ["cls_mm", "cls_b"], ["logits"]))
    g = helper.make_graph(nodes, cfg["name"], [inp], [out], inits)
    m = helper.make_model(g, opset_imports=[helper.make_opsetid("", OPSET)])
    m.ir_version = 9
    onnx.save(m, path, save_as_external_data=True, all_tensors_to_one_file=True, location=os.path.basename(path) + ".data")
    nparams = sum(int(np.prod(t.dims)) for t in inits)
    return nparams


def timeit(path, seq, threads, reps=30):
    so = ort.SessionOptions(); so.intra_op_num_threads = threads; so.inter_op_num_threads = 1
    so.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_ALL
    sess = ort.InferenceSession(path, so, providers=["CPUExecutionProvider"])
    ids = rng.integers(0, 1000, size=(1, seq), dtype=np.int64)
    for _ in range(5):
        sess.run(None, {"input_ids": ids})
    ts = []
    for _ in range(reps):
        t = time.perf_counter(); sess.run(None, {"input_ids": ids}); ts.append((time.perf_counter() - t) * 1000)
    return float(np.median(ts)), float(np.percentile(ts, 95))


CFGS = [
    dict(name="MiniLM-L6 (all-MiniLM-L6-v2 class)", layers=6, hidden=384, heads=12, inter=1536, vocab=30522),
    dict(name="BERT-small-12L-384 (bge-small class)", layers=12, hidden=384, heads=12, inter=1536, vocab=30522),
    dict(name="DeBERTa-v3-xsmall (Prompt Guard 2 22M class)", layers=12, hidden=384, heads=6, inter=1536, vocab=128100, rel=512),
    dict(name="DeBERTa-v3-base (PG2 86M / protectai v2 class)", layers=12, hidden=768, heads=12, inter=3072, vocab=128100, rel=512),
    dict(name="mDeBERTa-v3-base (PG2 86M multilingual / GLiNER-multi class)", layers=12, hidden=768, heads=12, inter=3072, vocab=250105, rel=512),
]

if __name__ == "__main__":
    os.makedirs("models", exist_ok=True)
    seqs = [int(s) for s in os.environ.get("SEQS", "64,200,512").split(",")]
    threads_list = [int(t) for t in os.environ.get("THREADS", "4,1").split(",")]
    print(f"onnxruntime {ort.__version__}, cpus={os.cpu_count()}")
    for cfg in CFGS:
        base = f"models/{cfg['name'].split(' ')[0]}"
        fp32 = base + ".onnx"; int8 = base + ".int8.onnx"
        n = build(cfg, fp32)
        quantize_dynamic(fp32, int8, weight_type=QuantType.QInt8)
        sz32 = os.path.getsize(fp32) + os.path.getsize(fp32 + ".data")
        sz8 = os.path.getsize(int8) + (os.path.getsize(int8 + ".data") if os.path.exists(int8 + ".data") else 0)
        print(f"\n## {cfg['name']}: params~{n/1e6:.1f}M, fp32 file {sz32/1e6:.0f} MB, int8 file {sz8/1e6:.0f} MB")
        for th in threads_list:
            for s in seqs:
                m32, p32 = timeit(fp32, s, th)
                m8, p8 = timeit(int8, s, th)
                print(f"threads={th} seq={s}: fp32 p50={m32:.1f}ms p95={p32:.1f}ms | int8 p50={m8:.1f}ms p95={p8:.1f}ms", flush=True)
