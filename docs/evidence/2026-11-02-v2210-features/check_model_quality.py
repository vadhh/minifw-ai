"""One labelled benign lab HTTP control, separate from inference/measurement acceptance."""
import json
from pathlib import Path
import sys

rows = json.loads(Path(sys.argv[1]).read_text())
sample = next(row['actual'] for row in rows if row['test'] == 'measured_packet_model_inference')
probability = sample['probability']
prediction = 'threat' if probability >= .5 else 'benign'
print('CONTROL known benign local HTTP GET /')
print('EXPECTED benign')
print('PREDICTED', prediction, 'PROBABILITY', probability)
print('MODE', sample.get('mode', 'pre-shadow candidate'))
print('This single control is not representative Financial/Education accuracy.')
if prediction != 'benign':
    print('FAIL: benign traffic classified as threat; model must remain evaluation-only')
    raise SystemExit(1)
print('PASS: this control only; representative validation still required')
