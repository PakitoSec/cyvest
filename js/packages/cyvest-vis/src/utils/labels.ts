export function truncateLabel(
  value: string,
  maxLength: number = 28,
  truncateMiddle: boolean = true
): string {
  if (maxLength < 4 || value.length <= maxLength) {
    return value;
  }

  if (!truncateMiddle) {
    return `${value.slice(0, maxLength - 1)}…`;
  }

  const leftLength = Math.ceil((maxLength - 1) / 2);
  const rightLength = Math.floor((maxLength - 1) / 2);
  return `${value.slice(0, leftLength)}…${value.slice(-rightLength)}`;
}
