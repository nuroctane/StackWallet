import { Badge, Button, EmptyState, Panel, StatusDot } from '@stackwallet/ui';

export function ApprovalRail() {
  return (
    <Panel
      as="aside"
      title="Approvals"
      meta="0 pending"
      className="sw-enter hidden min-[1100px]:flex"
    >
      <div className="flex h-full flex-col justify-between">
        <EmptyState
          title="Nothing to approve"
          description="Every signature request from any wallet, agent session or automation lands here before a ceremony starts."
        />
        <div className="flex flex-col gap-4 border-t border-edge p-4">
          <div className="flex flex-col gap-2">
            <div className="text-[11px] font-semibold tracking-[0.12em] text-muted uppercase">
              Parties
            </div>
            <StatusDot state="online" label="this device" />
            <StatusDot state="offline" label="no paired devices" />
          </div>
          <div className="flex flex-col gap-2">
            <div className="flex items-center gap-2">
              <span className="text-[11px] font-semibold tracking-[0.12em] text-muted uppercase">
                Policy
              </span>
              <Badge>phase 3</Badge>
            </div>
            <p className="text-[12px] text-faint">
              The default policy set is empty. Until policies exist, nothing here can gate a
              signature.
            </p>
            <div>
              <Button
                variant="ghost"
                size="sm"
                disabled
                title="Policies arrive with the policy engine in phase 3"
                className="-ml-2.5"
              >
                Add policy
              </Button>
            </div>
          </div>
        </div>
      </div>
    </Panel>
  );
}
