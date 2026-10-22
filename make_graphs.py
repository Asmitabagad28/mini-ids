#!/usr/bin/env python3
"""Create the three result graphs for the mini-ids string matcher project.

Reads:
  - result.csv      : times of the three algorithms vs. number of log lines
  - worstcase.csv   : worst-case times and comparison counts vs. text size

Writes:
  - graph_normal.png
  - graph_worstcase_time.png
  - graph_worstcase_comparisons.png
"""

import csv

import matplotlib

# Use a non-interactive backend so the script also works without a display.
matplotlib.use("Agg")

import matplotlib.pyplot as plt


def read_csv(filename):
    """Read a CSV file and return its rows as a list of dicts."""
    with open(filename, newline="") as handle:
        return list(csv.DictReader(handle))


def plot(ax, x, series, xlabel, ylabel, title):
    """Draw one log-log chart with markers and a legend on the given axes."""
    for label, y, marker in series:
        ax.plot(x, y, marker=marker, linestyle="-", label=label)

    # Log scale on both axes.
    ax.set_xscale("log")
    ax.set_yscale("log")

    # Titles, axis labels and legend.
    ax.set_title(title)
    ax.set_xlabel(xlabel)
    ax.set_ylabel(ylabel)
    ax.legend()
    ax.grid(True, which="both", linestyle=":", alpha=0.5)


def main():
    # ---- Graph 1: normal case, time vs. number of log lines ----
    rows = read_csv("result.csv")
    lines = [int(row["Lines"]) for row in rows]

    fig, ax = plt.subplots(figsize=(8, 6))
    plot(
        ax,
        lines,
        [
            ("Naive", [float(row["Naive (ms)"]) for row in rows], "o"),
            ("KMP", [float(row["KMP (ms)"]) for row in rows], "s"),
            ("Rabin-Karp", [float(row["Rabin-Karp (ms)"]) for row in rows], "^"),
        ],
        "Number of log lines",
        "Time (ms)",
        "Naive vs KMP vs Rabin-Karp on log files",
    )
    fig.tight_layout()
    fig.savefig("graph_normal.png", dpi=150)
    plt.close(fig)

    # ---- Graphs 2 and 3: worst case, driven by worstcase.csv ----
    rows = read_csv("worstcase.csv")
    size = [int(row["Size"]) for row in rows]

    # Graph 2: worst-case time vs. text size.
    fig, ax = plt.subplots(figsize=(8, 6))
    plot(
        ax,
        size,
        [
            ("Naive", [float(row["Naive (ms)"]) for row in rows], "o"),
            ("KMP", [float(row["KMP (ms)"]) for row in rows], "s"),
            ("Rabin-Karp", [float(row["Rabin-Karp (ms)"]) for row in rows], "^"),
        ],
        "Text size (characters)",
        "Time (ms)",
        "Worst-case time vs. text size",
    )
    fig.tight_layout()
    fig.savefig("graph_worstcase_time.png", dpi=150)
    plt.close(fig)

    # Graph 3: worst-case comparison counts vs. text size.
    fig, ax = plt.subplots(figsize=(8, 6))
    plot(
        ax,
        size,
        [
            ("Naive comparisons", [int(row["Naive Comparisons"]) for row in rows], "o"),
            ("KMP comparisons", [int(row["KMP Comparisons"]) for row in rows], "s"),
        ],
        "Text size (characters)",
        "Number of comparisons",
        "Worst-case comparisons vs. text size",
    )
    fig.tight_layout()
    fig.savefig("graph_worstcase_comparisons.png", dpi=150)
    plt.close(fig)

    print("Wrote graph_normal.png, graph_worstcase_time.png, graph_worstcase_comparisons.png")


if __name__ == "__main__":
    main()
