import time
import statistics
import threading
from typing import Dict, List, Union, Optional

try:
    from pythonping import ping
    PYTHONPING_AVAILABLE = True
except ImportError:
    PYTHONPING_AVAILABLE = False

from rich import print
from rich.console import Console
from rich.spinner import Spinner

def measure_connection_quality(
    target: str,
    min_duration: Optional[int] = 30,
    interval: float = 1.0,
    timeout: float = 2.0,
    include_extra_stats: bool = True,
    stop_event: Optional[threading.Event] = None
) -> Dict[str, Union[float, None]]:
    """
    Measures connection quality to a given host.
    If min_duration is provided, runs for at least that duration.
    If min_duration is None, runs indefinitely until stop_event is set.
    """
    if not PYTHONPING_AVAILABLE:
        return {
            "avg_latency":  0.0,
            "packet_loss":  100.0,
            "min_latency":  None,
            "max_latency":  None,
            "std_latency":  None
        }

    start_time = time.time()
    rtt_list: List[Optional[float]] = []
    total_sent = 0

    while True:
        # Stop if we've reached the finite duration
        if min_duration is not None and (time.time() - start_time) >= min_duration:
            break
        # Stop if the stop_event is triggered
        if stop_event is not None and stop_event.is_set():
            break

        try:
            resp = ping(target, count=1, timeout=timeout, verbose=False)
        except Exception:
            rtt_list.append(None)
        else:
            total_sent += 1
            if resp.packet_loss == 0:
                rtt_list.append(resp.rtt_avg_ms)
            else:
                rtt_list.append(None)

        time.sleep(interval)

    lost_count = sum(1 for rtt in rtt_list if rtt is None)
    success_count = total_sent - lost_count

    avg_latency = (sum(rtt for rtt in rtt_list if rtt is not None) / success_count) if success_count > 0 else 0.0
    packet_loss = (lost_count / total_sent * 100.0) if total_sent > 0 else 100.0

    results = {
        "avg_latency":  avg_latency,
        "packet_loss":  packet_loss,
        "min_latency":  None,
        "max_latency":  None,
        "std_latency":  None
    }

    if include_extra_stats and success_count > 0:
        successful_rtts = [r for r in rtt_list if r is not None]
        results["min_latency"] = min(successful_rtts)
        results["max_latency"] = max(successful_rtts)
        results["std_latency"] = statistics.pstdev(successful_rtts) if len(successful_rtts) > 1 else 0.0

    return results

def choose_duration(console: Console) -> Optional[int]:
    """
    Prompt the user to pick a test duration.
    Options: 30, 60, 120, 300 seconds or unlimited.
    Returns an integer duration or None for unlimited.
    """
    console.print("[bold cyan]Choose a test duration:[/bold cyan]")
    console.print("  1) 30 seconds")
    console.print("  2) 60 seconds")
    console.print("  3) 120 seconds")
    console.print("  4) 300 seconds")
    console.print("  5) Unlimited (press 's' to stop)")

    choice = console.input("[bold white]Enter the number of your choice:[/bold white] ")
    mapping = {
        "1": 30,
        "2": 60,
        "3": 120,
        "4": 300,
        "5": None  # Represents unlimited
    }
    if choice in mapping:
        return mapping[choice]
    else:
        console.print("[bold red]Invalid choice, defaulting to 30 seconds...[/bold red]")
        return 30

if __name__ == "__main__":
    console = Console()

    if not PYTHONPING_AVAILABLE:
        console.print("[bold red][ERROR][/bold red] pythonping is not installed.")
    else:
        console.print("[bold #00FFFF]==========================================[/bold #00FFFF]")
        console.print("[bold #FF69B4][CONNECTION SURVEY][/bold #FF69B4]")
        console.print("[bold #00FFFF]==========================================[/bold #00FFFF]\n")

        target = "8.8.8.8"
        duration = choose_duration(console)
        console.print(f"[bold yellow]You chose {'unlimited' if duration is None else str(duration) + 's'}[/bold yellow].")

        # Set shorter timeout for unlimited mode to respond faster
        timeout_value = 1.0 if duration is None else 2.0

        stop_event = threading.Event() if duration is None else None
        result_holder = {}

        def worker():
            res = measure_connection_quality(
                target,
                min_duration=duration,
                timeout=timeout_value,
                stop_event=stop_event
            )
            result_holder["data"] = res

        t = threading.Thread(target=worker, daemon=True)
        t.start()

        if stop_event is not None:
            def wait_for_stop():
                console.print("[bold cyan]Press 's' then Enter to stop the test.[/bold cyan]")
                while True:
                    user_input = console.input()
                    if user_input.strip().lower() == 's':
                        stop_event.set()
                        break
            stop_thread = threading.Thread(target=wait_for_stop, daemon=True)
            stop_thread.start()

        with console.status("[bold green]Measuring connection quality...[/bold green]", spinner="dots"):
            while t.is_alive():
                time.sleep(0.1)

        result = result_holder.get("data")
        if result is None:
            console.print("[bold red]No results returned (unexpected).[/bold red]")
        else:
            console.print(f"[bold green]Test complete for [white]{'unlimited' if duration is None else str(duration) + 's'}[/white] => {target}[/bold green]")
            console.print(f"  [#ADFF2F]Avg Latency:[/#ADFF2F]    [#87CEEB]{result['avg_latency']:.2f} ms[/#87CEEB]")
            console.print(f"  [#ADFF2F]Packet Loss:[/#ADFF2F]    [#87CEEB]{result['packet_loss']:.2f}%[/#87CEEB]")

            if result["min_latency"] is not None:
                console.print(f"  [#ADFF2F]Min Latency:[/#ADFF2F]    [#87CEEB]{result['min_latency']:.2f} ms[/#87CEEB]")
                console.print(f"  [#ADFF2F]Max Latency:[/#ADFF2F]    [#87CEEB]{result['max_latency']:.2f} ms[/#87CEEB]")
                console.print(f"  [#ADFF2F]Std Deviation:[/#ADFF2F]  [#87CEEB]{result['std_latency']:.2f} ms[/#87CEEB]")

        console.print("[bold cyan]Done.[/bold cyan]")
