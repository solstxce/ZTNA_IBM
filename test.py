import psutil

for process in [psutil.Process(pid) for pid in psutil.pids()]:
    try:
        process_name = process.name()
        process_mem = process.memory_percent()
        process_cpu = process.cpu_percent(interval=0.5)
    except psutil.NoSuchProcess as e:
        print(e.pid, "killed before analysis")
    else:
        print("Name:", process_name)
        print("CPU%:", process_cpu)
        print("MEM%:", process_mem)
        