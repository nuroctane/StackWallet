/**
 * Loader hook for `node --experimental-strip-types`: the workspace sources use
 * `.js` import specifiers (tsc style), which strip-types does not rewrite.
 * Retry a failed `.js` resolution as the sibling `.ts` file.
 */
export async function resolve(specifier, context, next) {
  try {
    return await next(specifier, context);
  } catch (error) {
    if (specifier.endsWith('.js') && (specifier.startsWith('./') || specifier.startsWith('../'))) {
      return next(`${specifier.slice(0, -3)}.ts`, context);
    }
    throw error;
  }
}
