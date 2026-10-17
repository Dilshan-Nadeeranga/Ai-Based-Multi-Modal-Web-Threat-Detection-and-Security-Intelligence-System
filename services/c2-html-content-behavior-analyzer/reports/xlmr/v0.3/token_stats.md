# XLM-R token lengths of page_text - v0.3

max_length = 512 tokens

## overall

| group | n | median | p90 | max | truncated |
|---|---:|---:|---:|---:|---:|
| all | 459 | 740 | 952 | 1889 | 299 (65.1 %) |

## per_language

| group | n | median | p90 | max | truncated |
|---|---:|---:|---:|---:|---:|
| en | 330 | 731 | 903 | 1050 | 214 (64.8 %) |
| mixed | 18 | 509 | 946 | 1180 | 9 (50.0 %) |
| other | 101 | 758 | 1139 | 1889 | 66 (65.3 %) |
| si | 7 | 945 | 1007 | 1054 | 7 (100.0 %) |
| ta | 3 | 921 | 987 | 1003 | 3 (100.0 %) |

## per_split

| group | n | median | p90 | max | truncated |
|---|---:|---:|---:|---:|---:|
| test | 68 | 718 | 943 | 1815 | 44 (64.7 %) |
| train | 322 | 742 | 945 | 1706 | 206 (64.0 %) |
| val | 69 | 765 | 1038 | 1889 | 49 (71.0 %) |
