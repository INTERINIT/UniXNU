"""Bounded patch of the pinned shipping watchdog's elapsed-time accounting.

The original sampler, 15/45/90-second checkpoints and 17-second host stall
assertions remain intact. Sleep-loop counts do not measure elapsed time when
the scheduler delays wakeups; use the actual monotonic Mach clock instead.
"""
import difflib
import hashlib
import json
from pathlib import Path
import subprocess


COMPONENT_PIN = "7e0d3d2ebaecd736784de0baa09254b7f63bc150"
SOURCE_SHA256 = "4ad86aa579652ce980dd02a30f8b2e9c12cc98c21187cc071dcdb1b71d313c2d"
PATCHED_SHA256 = "a613f68aa36294481f286a4cf92d4eb3ed5967fae72607a1a12aedbd7dbc884b"
PATCH_SHA256 = "b362dd5ed3d5e3b204fa9227127abc0608672b98d20a36250c1b3229f77f547e"
OLD_LOOP = """    static const unsigned checkpoints[] = {15, 45, 90};
    unsigned next = 0;
    for (unsigned tenths = 0; !__atomic_load_n(&w->done, __ATOMIC_ACQUIRE); ++tenths) {
        usleep(100000);
        if (next < 3 && tenths == checkpoints[next] * 10) {
            char text[64] = {};
            sample(*w, worker, text, sizeof text);
            report(text);
            ++next;
        }
    }
"""
NEW_LOOP = """    static const unsigned checkpoints[] = {15, 45, 90};
    const uint64_t watchdogStart = mach_absolute_time();
    unsigned next = 0;
    while (!__atomic_load_n(&w->done, __ATOMIC_ACQUIRE)) {
        usleep(100000);
        const uint64_t ticks = mach_absolute_time() - watchdogStart;
        // Divide before multiplying: the remainder product is bounded by two
        // uint32_t timebase values, and the quotient covers only this run.
        const uint64_t elapsedNanoseconds = ticks / watchdogTimebase.denom * watchdogTimebase.numer +
            (ticks % watchdogTimebase.denom) * watchdogTimebase.numer / watchdogTimebase.denom;
        if (next < 3 && elapsedNanoseconds >= uint64_t(checkpoints[next]) * 1000000000ull) {
            char text[64] = {};
            sample(*w, worker, text, sizeof text);
            report(text);
            ++next;
        }
    }
"""
CLOCK_SETUP = """    mach_timebase_info_data_t watchdogTimebase = {};
    if (mach_timebase_info(&watchdogTimebase) != KERN_SUCCESS || !watchdogTimebase.numer || !watchdogTimebase.denom) {
        Result r;
        r.vkResult = -12;
        snprintf(gFirstError, sizeof gFirstError, "watchdog monotonic clock unavailable");
        return r;
    }
"""


def sha(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def transform(original):
    if sha(original) != SOURCE_SHA256:
        raise ValueError("Pinned watchdog source differs; review instead of applying a loose replacement")
    include = "#include <mach/mach.h>\n"
    allocation = "    Watched *w = new Watched{};\n"
    if original.count(include) != 1 or original.count(allocation) != 1 or original.count(OLD_LOOP) != 1:
        raise ValueError("Expected exactly the pinned watchdog clock/include/loop boundaries")
    return original.replace(include, include + "#include <mach/mach_time.h>\n").replace(
        allocation, CLOCK_SETUP + allocation).replace(OLD_LOOP, NEW_LOOP)


def apply(tree, output):
    tree, output = Path(tree), Path(output)
    component = tree / "drivers/AdrenoMetal"
    source = component / "NativeTurnipSmoke.h"
    actual = subprocess.check_output(["git", "-C", str(component), "rev-parse", "HEAD"], text=True).strip()
    if actual != COMPONENT_PIN:
        raise ValueError("Unexpected AdrenoMetal component revision for the watchdog fix")
    # Git supplies the exact clean source even on an idempotent cached rerun.
    original = subprocess.check_output(["git", "-C", str(component), "show", COMPONENT_PIN + ":NativeTurnipSmoke.h"])
    original = original.decode("utf-8")
    changed = transform(original)
    if sha(changed) != PATCHED_SHA256:
        raise ValueError("The reviewed monotonic patch output differs")
    current = source.read_text(encoding="utf-8")
    if current not in (original, changed):
        raise ValueError("Preserve an independently modified watchdog source")
    if current != changed:
        source.write_text(changed, encoding="utf-8", newline="\n")
    if sha(source.read_text(encoding="utf-8")) != sha(changed):
        raise ValueError("The watchdog source did not retain the exact monotonic patch")
    patch = "".join(difflib.unified_diff(original.splitlines(keepends=True), changed.splitlines(keepends=True),
                                      fromfile="a/NativeTurnipSmoke.h", tofile="b/NativeTurnipSmoke.h"))
    recorded = Path(__file__).resolve().parents[2] / "patches/gpu/watchdog-monotonic.patch"
    if sha(patch) != PATCH_SHA256 or recorded.read_text(encoding="utf-8") != patch:
        raise ValueError("The published watchdog source patch differs")
    (output / "gpu27-watchdog-source.patch").write_text(patch, encoding="utf-8", newline="\n")
    report = {"component": "AdrenoMetal", "component_commit": COMPONENT_PIN, "source": "NativeTurnipSmoke.h",
              "source_before_sha256": SOURCE_SHA256, "source_after_sha256": sha(changed), "patch_sha256": sha(patch),
              "clock": "mach_absolute_time plus checked mach_timebase_info", "checkpoints_seconds": [15, 45, 90],
              "original_sampler_unchanged": True, "host_stall_seconds": 17,
              "host_assertions_unchanged": True, "qualification_at_patch_application": "not_run", "hardware_tested": False}
    (output / "gpu27-watchdog-source.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return report


def clock_fixture():
    """Compile both exact loop bodies against a deterministic delayed clock."""
    prefix = r'''#include <cassert>
#include <cstdint>
#include <cstdio>
namespace watchdog_clock_control {
struct Watched {int done;};
struct Timebase {uint32_t numer, denom;};
static uint64_t nanoseconds, wakeDelay, firstSample;
static unsigned samples;
static Watched *current;
static Timebase ratio;
static uint64_t mach_absolute_time() {return nanoseconds * ratio.denom / ratio.numer;}
static void usleep(unsigned) {
    nanoseconds += wakeDelay;
    if (nanoseconds >= 17000000000ull) current->done = 1;
}
static void sample(Watched &, int, char *, unsigned long) {
    if (!samples) firstSample = nanoseconds;
    nanoseconds += 300000000; // actual sampler's observation interval
}
static void report(const char *) {++samples;}
'''
    setup = '''    Watched state{};
    Watched *w = &state;
    current = w;
    [[maybe_unused]] const int worker = 0;
    [[maybe_unused]] const Timebase watchdogTimebase = ratio;
'''
    functions = "static void original() {\n" + setup + OLD_LOOP + "}\n"
    functions += "static void corrected() {\n" + setup + NEW_LOOP + "}\n"
    controls = r'''static void reset(uint64_t delay, Timebase scale) {
    nanoseconds = firstSample = samples = 0;
    wakeDelay = delay;
    ratio = scale;
}
static void check() {
    reset(125000000, {1, 1});
    original();
    assert(samples == 0); // 17s completes before 151 delayed wakeups
    reset(10000000, {1, 1});
    original();
    assert(samples == 3 && firstSample < 2000000000ull); // interrupted/early wakeups
    for (Timebase scale : {Timebase{1, 1}, Timebase{125, 3}}) {
        for (uint64_t delay : {10000000ull, 100000000ull, 125000000ull, 250000000ull}) {
            reset(delay, scale);
            corrected();
            assert(samples == 1);
            assert(firstSample >= 15000000000ull && firstSample < 16000000000ull);
        }
    }
    puts("PASS: exact shipping watchdog loops; delayed/early wakeups and both Mach timebase ratios");
}
}
int main() {watchdog_clock_control::check();}
'''
    return "#include <initializer_list>\n" + prefix + functions + controls


def qualify_clock(output, env):
    """A real host C++ check; its success does not replace the 17s stack test."""
    output = Path(output)
    source, binary = output / "gpu27-watchdog-clock-control.cpp", output / "gpu27-watchdog-clock-control"
    source.write_text(clock_fixture(), encoding="utf-8", newline="\n")
    log = output / "gpu27-watchdog-clock-control.log"
    with log.open("w", encoding="utf-8") as stream:
        subprocess.run(["xcrun", "clang++", "-std=c++17", "-O1", "-Wall", "-Wextra", "-Werror", str(source), "-o", str(binary)],
                       env=env, stdout=stream, stderr=subprocess.STDOUT, check=True)
        subprocess.run([str(binary)], env=env, stdout=stream, stderr=subprocess.STDOUT, check=True, timeout=10)
    if "PASS: exact shipping watchdog loops" not in log.read_text(encoding="utf-8"):
        raise ValueError("Actual host watchdog clock controls did not complete")
    (output / "gpu27-watchdog-clock-control.json").write_text(json.dumps({
        "status": "passed", "exact_old_and_patched_loop_bodies": True, "fixture_sha256": sha(clock_fixture()),
        "source_before_sha256": SOURCE_SHA256, "source_after_sha256": PATCHED_SHA256,
        "still_requires_real_17_second_stall_and_stack_control": True, "hardware_tested": False}, indent=2) + "\n")
