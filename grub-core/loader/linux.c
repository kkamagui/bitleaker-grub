#include <grub/types.h>
#include <grub/err.h>
#include <grub/linux.h>
#include <grub/misc.h>
#include <grub/file.h>
#include <grub/mm.h>
#include <grub/tpm.h>
#include <grub/efi/efi.h>
#include <grub/efi/api.h>
#include <grub/efi/tpm.h>
#include <grub/term.h>

struct newc_head
{
  char magic[6];
  char ino[8];
  char mode[8];
  char uid[8];
  char gid[8];
  char nlink[8];
  char mtime[8];
  char filesize[8];
  char devmajor[8];
  char devminor[8];
  char rdevmajor[8];
  char rdevminor[8];
  char namesize[8];
  char check[8];
} GRUB_PACKED;

struct grub_linux_initrd_component
{
  grub_file_t file;
  char *newc_name;
  grub_off_t size;
};

struct dir
{
  char *name;
  struct dir *next;
  struct dir *child;
};

static char
hex (grub_uint8_t val)
{
  if (val < 10)
    return '0' + val;
  return 'a' + val - 10;
}

static void
set_field (char *var, grub_uint32_t val)
{
  int i;
  char *ptr = var;
  for (i = 28; i >= 0; i -= 4)
    *ptr++ = hex((val >> i) & 0xf);
}

static grub_uint8_t *
make_header (grub_uint8_t *ptr,
	     const char *name, grub_size_t len,
	     grub_uint32_t mode,
	     grub_off_t fsize)
{
  struct newc_head *head = (struct newc_head *) ptr;
  grub_uint8_t *optr;
  grub_size_t oh = 0;
  grub_memcpy (head->magic, "070701", 6);
  set_field (head->ino, 0);
  set_field (head->mode, mode);
  set_field (head->uid, 0);
  set_field (head->gid, 0);
  set_field (head->nlink, 1);
  set_field (head->mtime, 0);
  set_field (head->filesize, fsize);
  set_field (head->devmajor, 0);
  set_field (head->devminor, 0);
  set_field (head->rdevmajor, 0);
  set_field (head->rdevminor, 0);
  set_field (head->namesize, len);
  set_field (head->check, 0);
  optr = ptr;
  ptr += sizeof (struct newc_head);
  grub_memcpy (ptr, name, len);
  ptr += len;
  oh = ALIGN_UP_OVERHEAD (ptr - optr, 4);
  grub_memset (ptr, 0, oh);
  ptr += oh;
  return ptr;
}

static void
free_dir (struct dir *root)
{
  if (!root)
    return;
  free_dir (root->next);
  free_dir (root->child);
  grub_free (root->name);
  grub_free (root);
}

static grub_size_t
insert_dir (const char *name, struct dir **root,
	    grub_uint8_t *ptr)
{
  struct dir *cur, **head = root;
  const char *cb, *ce = name;
  grub_size_t size = 0;
  while (1)
    {
      for (cb = ce; *cb == '/'; cb++);
      for (ce = cb; *ce && *ce != '/'; ce++);
      if (!*ce)
	break;

      for (cur = *root; cur; cur = cur->next)
	if (grub_memcmp (cur->name, cb, ce - cb)
	    && cur->name[ce - cb] == 0)
	  break;
      if (!cur)
	{
	  struct dir *n;
	  n = grub_zalloc (sizeof (*n));
	  if (!n)
	    return 0;
	  n->next = *head;
	  n->name = grub_strndup (cb, ce - cb);
	  if (ptr)
	    {
	      grub_dprintf ("linux", "Creating directory %s, %s\n", name, ce);
	      ptr = make_header (ptr, name, ce - name,
				 040777, 0);
	    }
	  size += ALIGN_UP ((ce - (char *) name)
			    + sizeof (struct newc_head), 4);
	  *head = n;
	  cur = n;
	}
      root = &cur->next;
    }
  return size;
}

grub_err_t
grub_initrd_init (int argc, char *argv[],
		  struct grub_linux_initrd_context *initrd_ctx)
{
  int i;
  int newc = 0;
  struct dir *root = 0;

  initrd_ctx->nfiles = 0;
  initrd_ctx->components = 0;

  initrd_ctx->components = grub_zalloc (argc
					* sizeof (initrd_ctx->components[0]));
  if (!initrd_ctx->components)
    return grub_errno;

  initrd_ctx->size = 0;

  for (i = 0; i < argc; i++)
    {
      const char *fname = argv[i];

      initrd_ctx->size = ALIGN_UP (initrd_ctx->size, 4);

      if (grub_memcmp (argv[i], "newc:", 5) == 0)
	{
	  const char *ptr, *eptr;
	  ptr = argv[i] + 5;
	  while (*ptr == '/')
	    ptr++;
	  eptr = grub_strchr (ptr, ':');
	  if (eptr)
	    {
	      grub_file_filter_disable_compression ();
	      initrd_ctx->components[i].newc_name = grub_strndup (ptr, eptr - ptr);
	      if (!initrd_ctx->components[i].newc_name)
		{
		  grub_initrd_close (initrd_ctx);
		  return grub_errno;
		}
	      initrd_ctx->size
		+= ALIGN_UP (sizeof (struct newc_head)
			    + grub_strlen (initrd_ctx->components[i].newc_name),
			     4);
	      initrd_ctx->size += insert_dir (initrd_ctx->components[i].newc_name,
					      &root, 0);
	      newc = 1;
	      fname = eptr + 1;
	    }
	}
      else if (newc)
	{
	  initrd_ctx->size += ALIGN_UP (sizeof (struct newc_head)
					+ sizeof ("TRAILER!!!") - 1, 4);
	  free_dir (root);
	  root = 0;
	  newc = 0;
	}
      grub_file_filter_disable_compression ();
      initrd_ctx->components[i].file = grub_file_open (fname);
      if (!initrd_ctx->components[i].file)
	{
	  grub_initrd_close (initrd_ctx);
	  return grub_errno;
	}
      initrd_ctx->nfiles++;
      initrd_ctx->components[i].size
	= grub_file_size (initrd_ctx->components[i].file);
      initrd_ctx->size += initrd_ctx->components[i].size;
    }

  if (newc)
    {
      initrd_ctx->size = ALIGN_UP (initrd_ctx->size, 4);
      initrd_ctx->size += ALIGN_UP (sizeof (struct newc_head)
				    + sizeof ("TRAILER!!!") - 1, 4);
      free_dir (root);
      root = 0;
    }
  
  return GRUB_ERR_NONE;
}

grub_size_t
grub_get_initrd_size (struct grub_linux_initrd_context *initrd_ctx)
{
  return initrd_ctx->size;
}

void
grub_initrd_close (struct grub_linux_initrd_context *initrd_ctx)
{
  int i;
  if (!initrd_ctx->components)
    return;
  for (i = 0; i < initrd_ctx->nfiles; i++)
    {
      grub_free (initrd_ctx->components[i].newc_name);
      grub_file_close (initrd_ctx->components[i].file);
    }
  grub_free (initrd_ctx->components);
  initrd_ctx->components = 0;
}

static grub_efi_guid_t tpm_guid = EFI_TPM_GUID;
static grub_efi_guid_t tpm2_guid = EFI_TPM2_GUID;

char* g_output_addr = (char*)0x80000;
int g_total_size = 64 * 1024;
int g_output_count = 0;

static void print_and_dump(const char *fmt, ...)
{
  va_list ap;
  int tmp_count;

  va_start (ap, fmt);
  tmp_count = grub_vprintf(fmt, ap);
  va_end (ap);

  va_start (ap, fmt);
  tmp_count = grub_vsnprintf(g_output_addr + g_output_count, g_total_size - g_output_count, fmt, ap);
  va_end (ap);
  g_output_count += tmp_count;
}

static grub_efi_boolean_t grub_tpm_handle_find(grub_efi_handle_t *tpm_handle,
                                              grub_efi_uint8_t *protocol_version)
{
  grub_efi_handle_t *handles;
  grub_efi_uintn_t num_handles;

  handles = grub_efi_locate_handle (GRUB_EFI_BY_PROTOCOL, &tpm_guid, NULL,
                                   &num_handles);
  if (handles && num_handles > 0) {
    *tpm_handle = handles[0];
    *protocol_version = 1;
    return 1;
  }

  handles = grub_efi_locate_handle (GRUB_EFI_BY_PROTOCOL, &tpm2_guid, NULL,
                                   &num_handles);
  if (handles && num_handles > 0) {
    *tpm_handle = handles[0];
    *protocol_version = 2;
    return 1;
  }


  return 0;
}

#ifdef TPM_SHA1_LOG_FORAMT
/*
 * Save event logs for event version 1
 */
static grub_err_t
tpm_save_event_log_v1(void)
{
  grub_efi_status_t status;
  grub_efi_tpm2_protocol_t *tpm;
  grub_efi_physical_address_t start;
  grub_efi_physical_address_t end;
  grub_efi_physical_address_t cur;
  grub_efi_boolean_t trunc;
  grub_efi_handle_t tpm_handle;
  grub_uint8_t protocol_version;
  TCG_PCR_EVENT *event;
  int event_version;
  int count = 0;
  int i;

  grub_printf("tpm event log show\n");

  if (!grub_tpm_handle_find(&tpm_handle, &protocol_version))
  {
    grub_printf("tpm_handle find error\n");
    return 0;
  }

  event_version = 1;
  print_and_dump("evet_version = %d\n", event_version);
  print_and_dump("TCG_PCR_EVENT size %lu TCG_PCR_HDR %lu\n", sizeof(TCG_PCR_EVENT), sizeof(TCG_PCR_HDR));

  tpm = grub_efi_open_protocol (tpm_handle, &tpm2_guid,
                               GRUB_EFI_OPEN_PROTOCOL_GET_PROTOCOL);
  status = efi_call_5 (tpm->get_event_log, tpm, event_version, &start, &end, &trunc);

  switch (status) {
  case GRUB_EFI_SUCCESS:
    break;
  case GRUB_EFI_DEVICE_ERROR:
    return grub_error (GRUB_ERR_IO, N_("Command failed"));
  case GRUB_EFI_INVALID_PARAMETER:
    return grub_error (GRUB_ERR_BAD_ARGUMENT, N_("Invalid parameter"));
  case GRUB_EFI_BUFFER_TOO_SMALL:
    return grub_error (GRUB_ERR_BAD_ARGUMENT, N_("Output buffer too small"));
  case GRUB_EFI_NOT_FOUND:
    return grub_error (GRUB_ERR_UNKNOWN_DEVICE, N_("TPM unavailable"));
  default:
    return grub_error (GRUB_ERR_UNKNOWN_DEVICE, N_("Unknown TPM error"));
  }

  print_and_dump("Start %p, End %p, Trunc %d\n", (void*)start, (void*)end, trunc);

  for (cur = start ; cur <= end ; )
  {
    count++;
    event = (TCG_PCR_EVENT *)cur;

    print_and_dump("[%d] PCR %d, Event %x, Event Size %d, SHA1= ",
      count, event->PCRIndex, event->EventType, event->EventSize);

    for (i = 0 ; i < 20 ; i++)
    {
      print_and_dump("%02x ", (event->digest[i]) & 0xFF);
    }
    print_and_dump("\n");

    cur = cur + sizeof(TCG_PCR_HDR) + event->EventSize;
    grub_refresh();
  }

  return 0;
}
#endif

/*
 * Save event logs for event version 2
 */
static grub_err_t
tpm_save_event_log_v2(void)
{
  grub_efi_status_t status;
  grub_efi_tpm2_protocol_t *tpm;
  grub_efi_physical_address_t start;
  grub_efi_physical_address_t end;
  grub_efi_physical_address_t cur;
  grub_efi_boolean_t trunc;
  grub_efi_handle_t tpm_handle;
  grub_uint8_t protocol_version;
  TCG_PCR_EVENT2 *event;
  TCG_PCR_EVENT *event_header;
  TCG_DIGEST_VALUE *digest;
  int event_version;
  int count = 0;
  int index_in_event;
  grub_efi_uint32_t digest_index;
  int event_size;
  int i;

  grub_printf("tpm event log show\n");

  if (!grub_tpm_handle_find(&tpm_handle, &protocol_version))
  {
    grub_printf("tpm_handle find error\n");
    return 0;
  }

  event_version = 2;
  print_and_dump("evet_version = %d\n", event_version);
  print_and_dump("TCG_PCR_EVENT size %lu TCG_PCR_EVENT2 size %lu\n", sizeof(TCG_PCR_EVENT), sizeof(TCG_PCR_EVENT2));
  grub_printf("Press any key to dump PCRs...\n");
  grub_getkey();

  tpm = grub_efi_open_protocol (tpm_handle, &tpm2_guid,
                               GRUB_EFI_OPEN_PROTOCOL_GET_PROTOCOL);
  status = efi_call_5 (tpm->get_event_log, tpm, event_version, &start, &end, &trunc);

  switch (status) {
  case GRUB_EFI_SUCCESS:
    break;
  case GRUB_EFI_DEVICE_ERROR:
    return grub_error (GRUB_ERR_IO, N_("Command failed"));
  case GRUB_EFI_INVALID_PARAMETER:
    return grub_error (GRUB_ERR_BAD_ARGUMENT, N_("Invalid parameter"));
  case GRUB_EFI_BUFFER_TOO_SMALL:
    return grub_error (GRUB_ERR_BAD_ARGUMENT, N_("Output buffer too small"));
  case GRUB_EFI_NOT_FOUND:
    return grub_error (GRUB_ERR_UNKNOWN_DEVICE, N_("TPM unavailable"));
  default:
    return grub_error (GRUB_ERR_UNKNOWN_DEVICE, N_("Unknown TPM error"));
  }

  print_and_dump("Start %p, End %p, Trunc %d\n", (void*)start, (void*)end, trunc);

  // First one is spefic header, so skip it
  event_header = (TCG_PCR_EVENT*) start;
  cur = (start + sizeof(TCG_PCR_HDR) + event_header->EventSize);
  while (cur <= end)
  {
    count++;
    event = (TCG_PCR_EVENT2 *)cur;

    grub_printf("Digest Count=%d.\n", event->Count);

    index_in_event = sizeof(TCG_PCR_EVENT2);
    for (digest_index = 0 ; digest_index < event->Count ; digest_index++)
    {
      digest = (TCG_DIGEST_VALUE *)(cur + index_in_event);
      switch(digest->AlgorithmID)
      {
        case TCG_ALG_SHA1:
          grub_printf("Digest is SHA1, Print it\n");
          grub_printf("[%d] PCR %d, Event %x, SHA1= ",
            count, event->PCRIndex, event->EventType);
          for (i = 0 ; i < TCG_ALG_SIZE_SHA1 ; i++)
          {
            grub_printf("%02x ", (digest->digest[i]) & 0xFF);
          }
          grub_printf("\n");

          index_in_event += TCG_ALG_SIZE_SHA1 + sizeof(TCG_DIGEST_VALUE);
          break;

        case TCG_ALG_SHA256:
          grub_printf("Digest is SHA256, Dump it\n");
          print_and_dump("[%d] PCR %d, Event %x, SHA256= ",
            count, event->PCRIndex, event->EventType);

          for (i = 0 ; i < TCG_ALG_SIZE_SHA256 ; i++)
          {
            print_and_dump("%02x ", (digest->digest[i]) & 0xFF);
          }
          print_and_dump("\n");

          index_in_event += TCG_ALG_SIZE_SHA256 + sizeof(TCG_DIGEST_VALUE);
          break;

        default:
          print_and_dump("Unsupported algorithm, Algorithm ID=%d\n", digest->AlgorithmID);
          return grub_error (GRUB_ERR_UNKNOWN_DEVICE, N_("Unknown TPM error"));
          break;
      }
    }
    // Get event size and skip it
    event_size = *(grub_efi_uint32_t *)(cur + index_in_event);
    index_in_event += event_size + sizeof(grub_efi_uint32_t);

    // Go to the next item.
    cur = cur + index_in_event;
    grub_refresh();
  }

  return 0;
}

grub_err_t
grub_initrd_load (struct grub_linux_initrd_context *initrd_ctx,
		  char *argv[], void *target)
{
  grub_uint8_t *ptr = target;
  int i;
  int newc = 0;
  struct dir *root = 0;
  grub_ssize_t cursize = 0;

  for (i = 0; i < initrd_ctx->nfiles; i++)
    {
      grub_memset (ptr, 0, ALIGN_UP_OVERHEAD (cursize, 4));
      ptr += ALIGN_UP_OVERHEAD (cursize, 4);

      if (initrd_ctx->components[i].newc_name)
	{
	  ptr += insert_dir (initrd_ctx->components[i].newc_name,
			     &root, ptr);
	  ptr = make_header (ptr, initrd_ctx->components[i].newc_name,
			     grub_strlen (initrd_ctx->components[i].newc_name),
			     0100777,
			     initrd_ctx->components[i].size);
	  newc = 1;
	}
      else if (newc)
	{
	  ptr = make_header (ptr, "TRAILER!!!", sizeof ("TRAILER!!!") - 1,
			     0, 0);
	  free_dir (root);
	  root = 0;
	  newc = 0;
	}

      cursize = initrd_ctx->components[i].size;
      if (grub_file_read (initrd_ctx->components[i].file, ptr, cursize)
	  != cursize)
	{
	  if (!grub_errno)
	    grub_error (GRUB_ERR_FILE_READ_ERROR, N_("premature end of file %s"),
			argv[i]);
	  grub_initrd_close (initrd_ctx);
	  return grub_errno;
	}
      grub_print_error();

      ptr += cursize;
    }
  if (newc)
    {
      grub_memset (ptr, 0, ALIGN_UP_OVERHEAD (cursize, 4));
      ptr += ALIGN_UP_OVERHEAD (cursize, 4);
      ptr = make_header (ptr, "TRAILER!!!", sizeof ("TRAILER!!!") - 1, 0, 0);
    }

  // Save TPM event log
  // SHA1 format
#ifdef TPM_SHA1_LOG_FORAMT
  tpm_save_event_log_v1();
#else
  // SHA256 format
  tpm_save_event_log_v2();
#endif

  free_dir (root);
  root = 0;
  return GRUB_ERR_NONE;
}
