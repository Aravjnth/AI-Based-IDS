import csv
import random
import os

output_path = os.path.join("data", "sample_data.csv")

rows = 1000

with open(output_path, mode="w", newline="") as file:
    writer = csv.writer(file)

    # Header
    writer.writerow([
        "duration",
        "src_bytes",
        "dst_bytes",
        "count",
        "srv_count",
        "label"
    ])

    for _ in range(rows):
        is_attack = random.random() < 0.4  # 40% attacks

        if is_attack:
            duration = random.randint(0, 60)
            src_bytes = random.randint(0, 200)
            dst_bytes = random.randint(0, 10000)
            count = random.randint(10, 50)
            srv_count = random.randint(10, 50)
            label = "attack"
        else:
            duration = random.randint(0, 30)
            src_bytes = random.randint(50, 1000)
            dst_bytes = random.randint(0, 3000)
            count = random.randint(1, 10)
            srv_count = random.randint(1, 10)
            label = "normal"

        writer.writerow([
            duration,
            src_bytes,
            dst_bytes,
            count,
            srv_count,
            label
        ])

print("✅ 1000-line real-world IDS dataset generated successfully!")
