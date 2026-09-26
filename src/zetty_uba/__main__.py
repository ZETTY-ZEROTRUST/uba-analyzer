"""Offline CLI: no credentials, environment file loading or external services."""

import argparse
from pathlib import Path
from time import perf_counter

from .datasets.common import verify_file, write_json

SOURCES = {
    'online-shop': {'bytes': 28630570, 'md5': '725822e13e09281b498e7cd5d082a039',
                    'url': 'https://zenodo.org/records/18895701', 'embargo': 300},
    'rbd24-phishing-desktop': {'bytes': 12559333, 'md5': 'c55ef9d902973ab50b21399f5e50fabe',
                              'url': 'https://zenodo.org/records/13787591', 'embargo': 86400},
    'rba': {'bytes': 1093700330, 'md5': 'cc1b1078b3929650e6c08678caffcc57',
            'url': 'https://zenodo.org/records/6782156', 'embargo': 3600},
}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('source', choices=SOURCES)
    p.add_argument('--input', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--max-train', type=int, default=10000)
    p.add_argument('--max-rba-rows', type=int, default=250000)
    p.add_argument('--supervised', action='store_true')
    args = p.parse_args()
    settings = SOURCES[args.source]
    started = perf_counter()
    try:
        if args.output.exists():
            raise ValueError('output_must_not_exist')
        manifest = verify_file(args.input, size=settings['bytes'], md5=settings['md5'])
        manifest.update(url=settings['url'], license='CC-BY-4.0')
        if args.source == 'online-shop':
            from .datasets.online_shop import load
            data = load(args.input)
        elif args.source == 'rbd24-phishing-desktop':
            from .datasets.rbd24 import load
            data = load(args.input)
        else:
            from .datasets.rba import load
            data = load(args.input, max_rows=args.max_rba_rows)
        prepared = perf_counter()
        from .training.benchmark import run
        result = run(data, args.output, source_manifest=manifest,
                     max_train=args.max_train, embargo_seconds=settings['embargo'],
                     supervised=args.supervised)
        result['preparation_seconds'] = prepared - started
        result['end_to_end_seconds'] = perf_counter() - started
        write_json(args.output / 'manifest.json', result)
    except (ValueError, OSError) as exc:
        # No raw input, credential or row values in errors.
        print(f'FAILED: {type(exc).__name__}: offline stage could not complete')
        raise SystemExit(2) from None


if __name__ == '__main__':
    main()
