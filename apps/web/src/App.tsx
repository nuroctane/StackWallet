import { useEffect, useState } from 'react';
import { createCoreClient, type CoreClient } from '@stackwallet/core-client';

import { ApprovalRail } from './shell/ApprovalRail.js';
import { DirectoryTree } from './shell/DirectoryTree.js';
import { MainPane } from './shell/MainPane.js';
import { StatusBar } from './shell/StatusBar.js';

export interface CoreStatus {
  backend: CoreClient['backend'];
  version?: string;
  reason?: string;
}

export function App() {
  const [core, setCore] = useState<CoreStatus>({ backend: 'unavailable', reason: 'loading' });

  useEffect(() => {
    let cancelled = false;
    void createCoreClient().then(async (client) => {
      if (cancelled) return;
      if (client.backend === 'unavailable') {
        setCore({
          backend: 'unavailable',
          reason: 'reason' in client ? String(client.reason) : 'unknown',
        });
        return;
      }
      try {
        setCore({ backend: client.backend, version: await client.coreVersion() });
      } catch (err) {
        setCore({
          backend: 'unavailable',
          reason: err instanceof Error ? err.message : String(err),
        });
      }
    });
    return () => {
      cancelled = true;
    };
  }, []);

  return (
    <div className="grid h-full grid-rows-[1fr_auto] bg-paper text-ink">
      <div className="grid min-h-0 grid-cols-[280px_1fr] gap-3 p-3 min-[1100px]:grid-cols-[280px_1fr_320px]">
        <DirectoryTree />
        <MainPane />
        <ApprovalRail />
      </div>
      <StatusBar core={core} />
    </div>
  );
}
