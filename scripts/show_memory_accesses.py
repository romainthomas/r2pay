import pathlib
import seaborn
import json
import collections

import seaborn as sns
import matplotlib.pyplot as plt
import pandas as pd

CWD = pathlib.Path(__file__).parent

trace_file = CWD / ".." / "assets" / "mem_trace.json"
trace = json.loads(trace_file.read_bytes())[0]

# Only keep the last 3000 elements
trace = trace[-3000:]

data_plot_dict = collections.defaultdict(list)

for idx, mem in enumerate(trace):
    data_plot_dict["Instruction Index"].append(idx)
    data_plot_dict["Instruction Address"].append(mem[0])
    data_plot_dict["Memory Address"].append(mem[1])
    data_plot_dict["Access Size"].append(mem[2])

data_plot = pd.DataFrame(dict(data_plot_dict))
f, ax = plt.subplots()
sns.scatterplot(x="Instruction Index", y="Memory Address",
                palette="Paired",
                hue="Access Size",
                linewidth=0,
                data=data_plot, ax=ax)
#plt.savefig("../figures/mem.svg")
plt.show()
