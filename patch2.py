import sys

with open("src/global_eevdf.bpf.c", "r") as f:
    text = f.read()

text = text.replace("        if (stats) __sync_fetch_and_add(&stats->top_k_improvements, 1);\n", "")

with open("src/global_eevdf.bpf.c", "w") as f:
    f.write(text)

