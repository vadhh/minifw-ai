"""Exercise the actual authenticated operator warning; credentials arrive on stdin."""
import json
import os
from pathlib import Path
import sys
from playwright.sync_api import sync_playwright

assert os.geteuid()!=0
credentials=json.load(sys.stdin)
output,expected=Path(sys.argv[1]),sys.argv[2]
assert expected in {'warning','recovered'}
with sync_playwright() as playwright:
    browser=playwright.chromium.launch(executable_path='/usr/bin/chromium',chromium_sandbox=True,
                                       args=['--disable-dev-shm-usage','--no-proxy-server'])
    try:
        context=browser.new_context(ignore_https_errors=True,viewport={'width':1280,'height':900})
        response=context.request.post('https://127.0.0.1:8443/auth/login',form=credentials)
        assert response.ok,response.status
        page=context.new_page()
        page.goto('https://127.0.0.1:8443/admin/policy',wait_until='domcontentloaded')
        warning=page.locator('#runtime-health-warning')
        if expected=='warning':
            page.wait_for_function("!document.getElementById('runtime-health-warning').hidden && document.getElementById('runtime-health-warning').textContent.startsWith('Protection checks unavailable')",timeout=15000)
        else:
            warning.wait_for(state='hidden',timeout=15000)
        rows=[]
        for width,height in [(1280,900),(390,844)]:
            page.set_viewport_size({'width':width,'height':height})
            page.screenshot(path=str(output/f'health-{expected}-{width}.png'))
            bounds=warning.bounding_box()
            if expected=='warning':
                assert bounds and bounds['x']>=0 and bounds['x']+bounds['width']<=width
            rows.append(dict(width=width,height=height,visible=warning.is_visible(),bounds=bounds))
        result=dict(expected=expected,browser=browser.version,viewports=rows,warning_text=warning.inner_text() if expected=='warning' else '',
                    scope='Chromium on isolated VM; screenshots and viewport checks, no physical-device or screen-reader acceptance')
        (output/f'browser-{expected}.json').write_text(json.dumps(result,indent=2)+'\n')
        print(json.dumps(result))
    finally:
        browser.close()
