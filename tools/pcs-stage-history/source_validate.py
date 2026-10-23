"""Optional source-only checks. Full collector acceptance runs from private PCS."""
import os
import shutil
import validate as v


def main():
    if os.environ.get('GITHUB_REPOSITORY') != 'justinchen13/mihomo':
        raise RuntimeError('source repository guard')
    v.OUT.mkdir(parents=True, exist_ok=False)
    v.RECORD.update(status='FAIL', scope='source Go only; no private collector checkout or release qualification')
    v.save()
    try:
        name = 'transport/anytls/session/stage_history_causal_test.go'
        shutil.copyfile(v.CANDIDATE/name, v.BASELINE/name)
        v.go_tests('baseline-negative',['./transport/anytls/session'],'^TestStageHistoryCursorRecoversIntermediatePublication$',cwd=v.BASELINE,negative=True)
        v.go_tests('session-listener-normal',['./transport/anytls/session','./listener/anytls'])
        v.go_tests('session-listener-race',['./transport/anytls/session','./listener/anytls'],race=True)
        v.go_tests('unix-route-normal',['./hub/route'],'^TestAnyTLSStage')
        v.go_tests('unix-route-race',['./hub/route'],'^TestAnyTLSStage',race=True)
        v.RECORD.update(status='PASS_SOURCE_GO_ONLY',release_status='NOT_COMPLETE_RELEASE_QUALIFICATION')
    finally:
        v.save()


if __name__ == '__main__': main()
