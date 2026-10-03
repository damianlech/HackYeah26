"""How far apart are token counts for the same text across tokenizers, and how good is chars/4?
Tokenizers available offline in this sandbox (bundled in PyPI wheels):
  - legacy Claude tokenizer (anthropic==0.18.1 wheel, anthropic/tokenizer.json)  -- NOT the current Claude tokenizer
  - Mistral SentencePiece v1 (32k vocab, Llama-2-style)       mistral_common/data/tokenizer.model.v1
  - Mistral Tekken 240911 (tiktoken-style, ~131k vocab)      mistral_common/data/tekken_240911.json
"""
import os, sentencepiece as spm, tokenizers, mistral_common
from mistral_common.tokens.tokenizers.tekken import Tekkenizer
D = os.path.join(os.path.dirname(mistral_common.__file__), "data")
claude_legacy = tokenizers.Tokenizer.from_file(os.environ.get("CLAUDE_LEGACY_TOKENIZER", "anthropic/tokenizer.json"))
sp = spm.SentencePieceProcessor(model_file=os.path.join(D, "tokenizer.model.v1"))
tek = Tekkenizer.from_file(os.path.join(D, "tekken_240911.json"))
T = {
 "english": "Please summarise the quarterly risk report for the equities desk. Highlight any breaches of the value-at-risk limit, the largest counterparty exposures, and recommended hedging actions for next week. Keep it under 200 words and avoid client names.",
 "polish": "Proszę podsumować kwartalny raport ryzyka dla desku akcji. Wskaż wszelkie przekroczenia limitu wartości zagrożonej, największe ekspozycje wobec kontrahentów oraz zalecane działania zabezpieczające na przyszły tydzień. Maksymalnie 200 słów, bez nazw klientów.",
 "python": "def reserve(ledger, user, amount):\n    with ledger.lock(user):\n        if ledger.spent(user) + amount > ledger.limit(user):\n            raise BudgetExceeded(user, ledger.limit(user))\n        ledger.add(user, amount)\n    return True\n",
 "json_tool": '{"type":"tool_use","id":"toolu_01A09q90qw90lq917835lq9","name":"get_portfolio","input":{"account_id":"ACC-77812","as_of":"2026-10-03","fields":["positions","pnl","var_99"]}}',
 "pesel_iban": "Klient: Jan Kowalski, PESEL 90010112345, IBAN PL61 1090 1014 0000 0712 1981 2874, tel. +48 600 700 800.",
}
print(f"{'text':<11}{'chars':>6}{'chars/4':>8}{'claude-legacy':>14}{'mistral-sp32k':>14}{'tekken131k':>11}{'max/min':>8}{'chars/4 err vs tekken':>23}")
for k, s in T.items():
    a = len(claude_legacy.encode(s).ids); b = len(sp.encode(s)); c = len(tek.encode(s, bos=False, eos=False))
    est = round(len(s) / 4)
    print(f"{k:<11}{len(s):>6}{est:>8}{a:>14}{b:>14}{c:>11}{max(a,b,c)/min(a,b,c):>8.2f}{(est-c)/c*100:>22.0f}%")
