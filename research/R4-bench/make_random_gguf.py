"""Write a random-weight F16 GGUF with the exact tensor shapes of a known small LLM.

Used only to measure llama.cpp CPU throughput (prefill / decode tok/s) for guard-model
size classes without downloading real weights. Speed is data-independent; outputs are garbage.

Usage (needs `pip install gguf numpy` or a llama.cpp checkout next to this file):
  python make_random_gguf.py lg3-1b gguf/lg3-1b-f16.gguf
  llama-quantize gguf/lg3-1b-f16.gguf gguf/lg3-1b-q8.gguf Q8_0
  llama-bench -m gguf/lg3-1b-q8.gguf -t <physical cores> -p 128,512 -n 32
"""
import sys
import numpy as np
sys.path.insert(0, "llama.cpp/gguf-py")  # prefer the checkout's gguf-py if present
import gguf

CFGS = {
    # Llama Guard 3 1B (pruned Llama 3.2 1B): 12 layers, ffn 6400 (per Meta model card)
    "lg3-1b":   dict(arch="llama", n_embd=2048, n_layer=12, n_head=32, n_kv=8, head_dim=64,  n_ff=6400,  vocab=128256, tied=True),
    # Llama 3.2 3B
    "llama-3b": dict(arch="llama", n_embd=3072, n_layer=28, n_head=24, n_kv=8, head_dim=128, n_ff=8192,  vocab=128256, tied=True),
    # Llama 3.1 8B / Llama Guard 3 8B
    "llama-8b": dict(arch="llama", n_embd=4096, n_layer=32, n_head=32, n_kv=8, head_dim=128, n_ff=14336, vocab=128256, tied=False),
    # Qwen3-0.6B / Qwen3Guard-Gen-0.6B
    "qwen3-0.6b": dict(arch="qwen3", n_embd=1024, n_layer=28, n_head=16, n_kv=8, head_dim=128, n_ff=3072, vocab=151936, tied=True),
    # Qwen3-4B / Qwen3Guard-Gen-4B
    "qwen3-4b": dict(arch="qwen3", n_embd=2560, n_layer=36, n_head=32, n_kv=8, head_dim=128, n_ff=9728, vocab=151936, tied=True),
}

rng = np.random.default_rng(0)


def rand(shape):
    return (rng.standard_normal(shape, dtype=np.float32) * 0.02).astype(np.float16)


def main(name, out):
    c = CFGS[name]
    a = c["arch"]
    w = gguf.GGUFWriter(out, a)
    w.add_context_length(4096)
    w.add_embedding_length(c["n_embd"])
    w.add_block_count(c["n_layer"])
    w.add_feed_forward_length(c["n_ff"])
    w.add_head_count(c["n_head"])
    w.add_head_count_kv(c["n_kv"])
    w.add_layer_norm_rms_eps(1e-6)
    w.add_rope_dimension_count(c["head_dim"])
    w.add_rope_freq_base(1e6)
    w.add_key_length(c["head_dim"])
    w.add_value_length(c["head_dim"])
    w.add_vocab_size(c["vocab"])
    w.add_tokenizer_model("none")
    w.add_file_type(gguf.LlamaFileType.MOSTLY_F16)

    E, H, K, D, F, V = c["n_embd"], c["n_head"], c["n_kv"], c["head_dim"], c["n_ff"], c["vocab"]
    tensors = [("token_embd.weight", (V, E), np.float16), ("output_norm.weight", (E,), np.float32)]
    if not c["tied"]:
        tensors.append(("output.weight", (V, E), np.float16))
    for i in range(c["n_layer"]):
        p = f"blk.{i}."
        tensors += [
            (p + "attn_norm.weight", (E,), np.float32),
            (p + "attn_q.weight", (H * D, E), np.float16),
            (p + "attn_k.weight", (K * D, E), np.float16),
            (p + "attn_v.weight", (K * D, E), np.float16),
            (p + "attn_output.weight", (E, H * D), np.float16),
            (p + "ffn_norm.weight", (E,), np.float32),
            (p + "ffn_gate.weight", (F, E), np.float16),
            (p + "ffn_up.weight", (F, E), np.float16),
            (p + "ffn_down.weight", (E, F), np.float16),
        ]
        if a == "qwen3":
            tensors += [(p + "attn_q_norm.weight", (D,), np.float32), (p + "attn_k_norm.weight", (D,), np.float32)]
    for n, shp, dt in tensors:
        w.add_tensor_info(n, shp, np.dtype(dt), int(np.prod(shp)) * np.dtype(dt).itemsize)
    w.write_header_to_file()
    w.write_kv_data_to_file()
    w.write_ti_data_to_file()
    total = 0
    for n, shp, dt in tensors:
        arr = np.ones(shp, dtype=np.float32) if len(shp) == 1 else rand(shp)
        w.write_tensor_data(arr.astype(dt))
        total += int(np.prod(shp))
    w.close()
    print(f"{name}: wrote {out}, params={total/1e9:.2f}B")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
