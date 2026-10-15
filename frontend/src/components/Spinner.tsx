export default function Spinner({ size = 6 }: { size?: number }) {
  return (
    <div
      style={{ width: `${size * 4}px`, height: `${size * 4}px` }}
      className="border-2 border-emerald-600 border-t-transparent rounded-full animate-spin"
    />
  );
}
