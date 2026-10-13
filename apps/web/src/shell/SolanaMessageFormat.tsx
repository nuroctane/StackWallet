import { Field, Select } from '@stackwallet/ui';

export function SolanaMessageFormat({
  value,
  disabled,
  onChange,
}: {
  value: 'legacy' | 'v0';
  disabled: boolean;
  onChange: (value: 'legacy' | 'v0') => void;
}) {
  return (
    <div className="space-y-2">
      <Field label="Message format" htmlFor="solana-message-format">
        <Select
          id="solana-message-format"
          value={value}
          disabled={disabled}
          onChange={(e) => onChange(e.target.value === 'v0' ? 'v0' : 'legacy')}
        >
          <option value="legacy">Legacy</option>
          <option value="v0">Versioned v0</option>
        </Select>
      </Field>
      <p className="text-[11px] text-faint">
        Devnet SOL only. Both formats use inline accounts for one transfer and no address lookup
        tables. Approval expires with the blockhash; an expired transfer needs a fresh proposal.
      </p>
    </div>
  );
}
