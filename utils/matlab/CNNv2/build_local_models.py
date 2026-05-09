#!/usr/bin/env python3
import argparse
import shutil
import subprocess
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
CORE_DIRS = {
    "core0": "cnn-nexmon-core-0-cpp-mcu-v46-dense-mini-core-0",
    "core1": "cnn-nexmon-core-1-cpp-mcu-v1-impulse-#1",
    "core2": "cnn-nexmon-core-2-cpp-mcu-v1-impulse-#1",
    "core3": "cnn-nexmon-core-3-cpp-mcu-v1-impulse-#1",
}


def collect_sources(core_dir: Path) -> list[str]:
    sdk = core_dir / "edge-impulse-sdk"
    sources = [BASE_DIR / "tools" / "local_runner.cpp"]
    sources += sorted((core_dir / "tflite-model").glob("*.cpp"))
    sources += [
        sdk / "classifier" / "ei_run_classifier_c.cpp",
        sdk / "dsp" / "memory.cpp",
        sdk / "dsp" / "dct" / "fast-dct-fft.cpp",
        sdk / "dsp" / "image" / "processing.cpp",
        sdk / "dsp" / "kissfft" / "kiss_fft.cpp",
        sdk / "dsp" / "kissfft" / "kiss_fftr.cpp",
        sdk / "porting" / "posix" / "debug_log.cpp",
        sdk / "porting" / "posix" / "ei_classifier_porting.cpp",
        sdk / "tensorflow" / "lite" / "c" / "common.c",
    ]
    sources += sorted((sdk / "tensorflow").rglob("*.cc"))
    sources += sorted((sdk / "third_party").rglob("*.cc"))
    return [str(p) for p in sources if p.exists()]


def build_core(core: str, clean: bool = False) -> Path:
    core_dir = BASE_DIR / CORE_DIRS[core]
    build_dir = BASE_DIR / "build" / core
    if clean and build_dir.exists():
        shutil.rmtree(build_dir)
    build_dir.mkdir(parents=True, exist_ok=True)
    output = build_dir / "app"
    sdk = core_dir / "edge-impulse-sdk"
    cmd = [
        "clang++",
        "-std=c++14",
        "-O3",
        "-DNDEBUG",
        "-DEI_PORTING_POSIX=1",
        "-Wno-deprecated-declarations",
        "-Wno-unused-parameter",
        "-Wno-missing-field-initializers",
        "-I", str(core_dir),
        "-I", str(sdk),
        "-I", str(sdk / "CMSIS" / "DSP" / "Include"),
        "-I", str(sdk / "CMSIS" / "NN" / "Include"),
        "-I", str(sdk / "third_party" / "gemmlowp"),
        "-I", str(sdk / "third_party" / "flatbuffers" / "include"),
        "-I", str(sdk / "third_party" / "ruy"),
        *collect_sources(core_dir),
        "-o", str(output),
    ]
    subprocess.run(cmd, check=True)
    return output


def main() -> None:
    parser = argparse.ArgumentParser(description="Compila los cuatro modelos locales de Edge Impulse.")
    parser.add_argument("--core", choices=sorted(CORE_DIRS), help="Compila solo un core.")
    parser.add_argument("--clean", action="store_true", help="Borra el build previo antes de compilar.")
    args = parser.parse_args()
    cores = [args.core] if args.core else sorted(CORE_DIRS)
    for core in cores:
        binary = build_core(core, clean=args.clean)
        print(f"{core}: {binary}")


if __name__ == "__main__":
    main()
