import { Panel, StatusDot } from '@stackwallet/ui';

export function ApprovalRail() {
  return (
    <Panel
      as="aside"
      title="Approvals"
      meta="0 pending"
      className="sw-enter hidden min-[1100px]:flex"
    >
      <div className="flex h-full flex-col justify-between p-4">
        <p className="text-muted">
          Every signature request from any wallet, agent session or automation lands here before a
          ceremony starts.
        </p>
        <div className="flex flex-col gap-2 border-t border-edge pt-3">
          <div className="text-[11px] font-semibold uppercase tracking-[0.12em] text-muted">
            Parties
          </div>
          <StatusDot state="online" label="this device" />
          <StatusDot state="offline" label="no paired devices" />
        </div>
      </div>
    </Panel>
  );
}
