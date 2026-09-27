"""Full study entry point, independent of the legacy service runtime."""
import argparse
import json
from pathlib import Path
from ..datasets.common import verify_file
from .data import prepare_rba, export_observations


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    sub=parser.add_subparsers(dest='command',required=True)
    prepare=sub.add_parser('prepare')
    prepare.add_argument('--source',required=True)
    prepare.add_argument('--input',type=Path,required=True)
    prepare.add_argument('--output',type=Path,required=True)
    prepare.add_argument('--catalog',type=Path,default=Path('docs/ml/01-data-audit/sources.json'))
    train=sub.add_parser('train')
    train.add_argument('--profile',choices=('cpu-full','colab-gpu-v1','colab-gpu-v2','colab-gpu-v3'),default='cpu-full')
    train.add_argument('--train-fraction',type=float,choices=(.4,.5),default=.5)
    train.add_argument('--prepared',type=Path,required=True)
    train.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    if args.command=='train':
        from .runner import run
        run(args.prepared,args.output,train_fraction=args.train_fraction,profile=args.profile)
        return
    if args.output.exists():raise ValueError('prepared_output_exists; reuse COMPLETED data or choose a new directory')
    if args.source=='rba':
        prepare_rba(args.input,args.output)
    elif args.source=='online-shop':
        from ..datasets.online_shop import load
        source=verify_file(args.input,size=28630570,md5='725822e13e09281b498e7cd5d082a039')
        export_observations(load(args.input),args.output,source_manifest=source,embargo=300,previous_test_inspected=True)
    else:
        from ..datasets.rbd24 import load
        catalog=json.loads(args.catalog.read_text())
        record=next(r for r in catalog if r['id']==13787591)
        specification=next((f for f in record['files'] if f['name']==args.source),None)
        if specification is None:raise ValueError('unknown_source')
        source=verify_file(args.input,size=specification['size'],md5=specification['checksum'].split(':')[1])
        source.update(url=record['url'],license=record['license'],file=specification['name'])
        name='rbd24-13787591-'+Path(args.source).stem.lower().replace('_','-')
        data=load(args.input,max_rows=1000000,source=name)
        export_observations(data,args.output,source_manifest=source,embargo=86400,
                            previous_test_inspected=args.source=='Phishing_desktop.parquet')


if __name__=='__main__':main()
