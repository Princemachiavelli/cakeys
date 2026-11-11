/* PC/SC reachability probe: prints raw SCardEstablishContext / SCardListReaders codes.
 * SCARD_E_NO_READERS_AVAILABLE (0x8010002e) means pcscd accepted us but sees no reader;
 * access or service errors mean pcscd (or polkit) refused the caller. */
#include <stdio.h>
#include <winscard.h>
int main(void) {
  SCARDCONTEXT ctx; DWORD len = 0;
  LONG rc = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &ctx);
  printf("SCardEstablishContext: 0x%08lx %s\n", (unsigned long)rc, pcsc_stringify_error(rc));
  if (rc != SCARD_S_SUCCESS) return 2;
  rc = SCardListReaders(ctx, NULL, NULL, &len);
  printf("SCardListReaders:      0x%08lx %s\n", (unsigned long)rc, pcsc_stringify_error(rc));
  return 0;
}
