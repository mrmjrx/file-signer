"""Test-runner script.  Allows for timing tests of the CLI's functionality"""

from main import compute_signature_and_key_pair
from crypto import VALID_ENCRYPTION_ALGORITHMS
from multiprocessing.pool import Pool
from collections import defaultdict
from pathlib import Path
from time import perf_counter
from statistics import stdev
from random import shuffle
from argparse import Namespace, ArgumentParser

TEST_COUNT: int = 250
"""The number of tests to run, per algorithm"""

HEX_FP: Path = Path(input(".hex file: "))
"""The path to the .hex file to parse for each test_run"""


def test_runner(algorithm: str, fp: Path) -> tuple[str, float]:
    """
    Function to run an individual signature test using ``algorithm`` on the .hex file at ``fp``
    :param algorithm: the algorithm name, as if passed as a CLI argument
    :param fp: the file path of the hex file to generate the signature of
    :return: the result of the test, in the form (algorithm, test_time) - algorithm is for processing purposes
    """
    start_time: float = perf_counter()
    _ = compute_signature_and_key_pair(fp, algorithm, None, None, None)

    return algorithm, perf_counter() - start_time


def test_main() -> int:
    """
    The main function of the test-runner.
    Creates the test pool, and executes all required tests.
    :return: the UNIX exit code (0 for success)
    """
    arg_parser: ArgumentParser = ArgumentParser(
        prog="FileSigner_timetest",
        description="Program to test the signature times of each algorithm of the FileSigner CLI"
    )

    arg_parser.add_argument("fp", help="The path to the .hex file to parse, in order to test each"
                                       "algorithm")
    arg_parser.add_argument("--test-count", default=TEST_COUNT, type=int, help="The number of instances to run, per"
                                                                               "algorithm")

    namespace: Namespace = arg_parser.parse_args()

    hex_fp: Path = Path(namespace.fp)
    if not hex_fp.exists() or not hex_fp.suffix == ".hex":
        raise ValueError(f"{hex_fp} is not a valid .hex file")

    starmap_args: list[tuple[str, Path]] = []
    for algorithm in VALID_ENCRYPTION_ALGORITHMS:
        for _ in range(namespace.test_count):
            starmap_args.append((algorithm, hex_fp))

    shuffle(starmap_args)

    print(f"Processing {len(starmap_args)} signature(s)...")

    pool_start_time: float = perf_counter()
    with Pool() as pool:
        results: list[tuple[str, float]] = pool.starmap(test_runner, starmap_args)

    algorithm_times_dict: defaultdict[str, list[float]] = defaultdict(lambda: [])
    for algorithm, time in results:
        algorithm_times_dict[algorithm].append(time)

    print("\n --- RESULTS ---")
    print(f"{"ALGORITHM":^{max(map(len, VALID_ENCRYPTION_ALGORITHMS))}} \t {"MEAN":^10} \t {"MAX":^10}"
          f"\t {"MIN":^10} \t {"STD DEV":^12}")

    for algorithm, times in algorithm_times_dict.items():
        sum_time_ms: int = round(sum(times) * 10 ** 3)

        print(
            f"{algorithm} \t AVG {sum_time_ms // TEST_COUNT:>4}ms \t MAX {round(max(times) * 10 ** 3):>4}ms "
            f"\t MIN {round(min(times) * 10 ** 3):>4}ms \t STDEV {round(stdev(times) * 10 ** 3):>4}ms")

    print(f"\nProcessed {len(starmap_args)} signatures in {perf_counter() - pool_start_time:.1f}s")

    return 0


if __name__ == '__main__':
    quit(test_main())
