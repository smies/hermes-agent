export function bindOwnedParentControl(onLoss) {
  if (typeof onLoss !== 'function') throw new TypeError('parent loss handler required');
  const input = process.stdin;
  if (!input || input.destroyed || input.readableEnded || input.isTTY) {
    throw new Error('owned parent control channel required');
  }
  let live = true;
  const lost = () => {
    if (!live) return;
    live = false;
    try { onLoss(); } catch {}
  };
  input.once('end', lost);
  input.once('error', lost);
  input.once('close', lost);
  input.resume();
  return Object.freeze({
    live: () => live && !input.destroyed && !input.readableEnded,
    release() {
      input.off('end', lost);
      input.off('error', lost);
      input.off('close', lost);
      live = false;
    },
  });
}
