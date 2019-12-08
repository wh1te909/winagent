import asyncio

async def ping_check(cmd):
    proc = await asyncio.create_subprocess_exec(
        *cmd['cmd'],
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE
    )
    stdout, stderr = await proc.communicate()

    success = ["Reply", "bytes", "time", "TTL"]
    status = ""

    if stdout:
        output = stdout.decode("utf-8", errors="ignore")
        if all(x in output for x in success):
            status = "passing"
        else:
            status = "failing"
    
    if stderr:
        status = "failing"
    
    print(status)
    return status


def make_chunks(l, n):
    for i in range(0, len(l), n):
        yield l[i : i + n]

def run_asyncio_commands(tasks, max_concurrent_tasks=0):

    all_results = []

    if max_concurrent_tasks == 0:
        chunks = [tasks]
        num_chunks = len(chunks)
    else:
        chunks = make_chunks(l=tasks, n=max_concurrent_tasks)
        num_chunks = len(list(make_chunks(l=tasks, n=max_concurrent_tasks)))

    if asyncio.get_event_loop().is_closed():
        asyncio.set_event_loop(asyncio.new_event_loop())

    asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
    loop = asyncio.get_event_loop()

    chunk = 1
    for tasks_in_chunk in chunks:
        commands = asyncio.gather(*tasks_in_chunk)
        results = loop.run_until_complete(commands)
        all_results += results
        chunk += 1

    loop.close()
    return all_results


def test_ping_check():
    tasks = []
    pings = []
    ips = ['8.8.8.8', 'google.com', '1.1.1.1', 'ak4j287asdjashdk45345kjad', 'facebook.com', '0.0.0.0']

    for ip in ips:
        pings.append({"cmd": ["ping", ip]})
    
    for ping in pings:
        tasks.append(ping_check(ping))
    
    results = run_asyncio_commands(tasks, max_concurrent_tasks=20)
    
    assert results == ['passing', 'passing', 'passing', 'failing', 'passing', 'failing']