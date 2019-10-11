/* chainloader.c - boot another boot loader */
/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2002,2004,2006,2007,2008  Free Software Foundation, Inc.
 *
 *  GRUB is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  GRUB is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with GRUB.  If not, see <http://www.gnu.org/licenses/>.
 */

/* TODO: support load options.  */

#include <grub/loader.h>
#include <grub/file.h>
#include <grub/err.h>
#include <grub/device.h>
#include <grub/disk.h>
#include <grub/misc.h>
#include <grub/charset.h>
#include <grub/mm.h>
#include <grub/types.h>
#include <grub/dl.h>
#include <grub/efi/api.h>
#include <grub/efi/efi.h>
#include <grub/efi/disk.h>
#include <grub/command.h>
#include <grub/i18n.h>
#include <grub/net.h>
#if defined (__i386__) || defined (__x86_64__)
#include <grub/macho.h>
#include <grub/i386/macho.h>
#endif
#include <grub/term.h>
#include <grub/efi/tpm.h>
#include <grub/lib/hexdump.h>

GRUB_MOD_LICENSE ("GPLv3+");

static grub_dl_t my_mod;

static grub_efi_physical_address_t address;
static grub_efi_uintn_t pages;
static grub_efi_device_path_t *file_path;
static grub_efi_handle_t image_handle;
static grub_efi_char16_t *cmdline;

/* Hook functions. */
grub_efi_status_t hook_get_capability (struct grub_efi_tpm2_protocol *this,
          EFI_TCG2_BOOT_SERVICE_CAPABILITY *ProtocolCapability);
grub_efi_status_t hook_get_event_log (struct grub_efi_tpm2_protocol *this,
          EFI_TCG2_EVENT_LOG_FORMAT event_log_format,
          grub_efi_physical_address_t *event_log_location,
          grub_efi_physical_address_t *event_log_last_entry,
          grub_uint8_t *EventLogTruncated);
grub_efi_status_t hook_hash_log_extend_event (struct grub_efi_tpm2_protocol *this,
          grub_uint64_t flags,
          grub_efi_physical_address_t data_to_hash,
          grub_uint64_t data_to_hashlen,
          EFI_TCG2_EVENT *efi_tcg_event);
grub_efi_status_t hook_submit_command (struct grub_efi_tpm2_protocol *this,
          grub_uint32_t input_parameter_block_size,
          grub_uint8_t *input_parameter_block,
          grub_uint32_t output_parameter_block_size,
          grub_uint8_t *outupt_parameter_block);

/* Export functions in callunwrap.S */
grub_efi_status_t EXPORT_FUNC(efi_unwrap_2_get_capability) (struct grub_efi_tpm2_protocol *this,
          EFI_TCG2_BOOT_SERVICE_CAPABILITY *ProtocolCapability);
grub_efi_status_t EXPORT_FUNC(efi_unwrap_5_get_event_log) (struct grub_efi_tpm2_protocol *this,
          EFI_TCG2_EVENT_LOG_FORMAT event_log_format,
          grub_efi_physical_address_t *event_log_location,
          grub_efi_physical_address_t *event_log_last_entry,
          grub_uint8_t *EventLogTruncated);
grub_efi_status_t EXPORT_FUNC(efi_unwrap_5_hash_log_extend_event) (struct grub_efi_tpm2_protocol *this,
          grub_uint64_t flags,
          grub_efi_physical_address_t data_to_hash,
          grub_uint64_t data_to_hashlen,
          EFI_TCG2_EVENT *efi_tcg_event);
grub_efi_status_t EXPORT_FUNC(efi_unwrap_5_submit_command) (struct grub_efi_tpm2_protocol *this,
          grub_uint32_t input_parameter_block_size,
          grub_uint8_t *input_parameter_block,
          grub_uint32_t output_parameter_block_size,
          grub_uint8_t *outupt_parameter_block);

static grub_err_t
grub_chainloader_unload (void)
{
  grub_efi_boot_services_t *b;

  b = grub_efi_system_table->boot_services;
  efi_call_1 (b->unload_image, image_handle);
  efi_call_2 (b->free_pages, address, pages);

  grub_free (file_path);
  grub_free (cmdline);
  cmdline = 0;
  file_path = 0;

  grub_dl_unref (my_mod);
  return GRUB_ERR_NONE;
}

static grub_err_t
grub_chainloader_boot (void)
{
  grub_efi_boot_services_t *b;
  grub_efi_status_t status;
  grub_efi_uintn_t exit_data_size;
  grub_efi_char16_t *exit_data = NULL;

  b = grub_efi_system_table->boot_services;
  status = efi_call_3 (b->start_image, image_handle, &exit_data_size, &exit_data);
  if (status != GRUB_EFI_SUCCESS)
    {
      if (exit_data)
	{
	  char *buf;

	  buf = grub_malloc (exit_data_size * 4 + 1);
	  if (buf)
	    {
	      *grub_utf16_to_utf8 ((grub_uint8_t *) buf,
				   exit_data, exit_data_size) = 0;

	      grub_error (GRUB_ERR_BAD_OS, buf);
	      grub_free (buf);
	    }
	}
      else
	grub_error (GRUB_ERR_BAD_OS, "unknown error");
    }

  if (exit_data)
    efi_call_1 (b->free_pool, exit_data);

  grub_loader_unset ();

  return grub_errno;
}

static void
copy_file_path (grub_efi_file_path_device_path_t *fp,
		const char *str, grub_efi_uint16_t len)
{
  grub_efi_char16_t *p;
  grub_efi_uint16_t size;

  fp->header.type = GRUB_EFI_MEDIA_DEVICE_PATH_TYPE;
  fp->header.subtype = GRUB_EFI_FILE_PATH_DEVICE_PATH_SUBTYPE;

  size = grub_utf8_to_utf16 (fp->path_name, len * GRUB_MAX_UTF16_PER_UTF8,
			     (const grub_uint8_t *) str, len, 0);
  for (p = fp->path_name; p < fp->path_name + size; p++)
    if (*p == '/')
      *p = '\\';

  /* File Path is NULL terminated */
  fp->path_name[size++] = '\0';
  fp->header.length = size * sizeof (grub_efi_char16_t) + sizeof (*fp);
}

static grub_efi_device_path_t *
make_file_path (grub_efi_device_path_t *dp, const char *filename)
{
  char *dir_start;
  char *dir_end;
  grub_size_t size;
  grub_efi_device_path_t *d;

  dir_start = grub_strchr (filename, ')');
  if (! dir_start)
    dir_start = (char *) filename;
  else
    dir_start++;

  dir_end = grub_strrchr (dir_start, '/');
  if (! dir_end)
    {
      grub_error (GRUB_ERR_BAD_FILENAME, "invalid EFI file path");
      return 0;
    }

  size = 0;
  d = dp;
  while (1)
    {
      size += GRUB_EFI_DEVICE_PATH_LENGTH (d);
      if ((GRUB_EFI_END_ENTIRE_DEVICE_PATH (d)))
	break;
      d = GRUB_EFI_NEXT_DEVICE_PATH (d);
    }

  /* File Path is NULL terminated. Allocate space for 2 extra characters */
  /* FIXME why we split path in two components? */
  file_path = grub_malloc (size
			   + ((grub_strlen (dir_start) + 2)
			      * GRUB_MAX_UTF16_PER_UTF8
			      * sizeof (grub_efi_char16_t))
			   + sizeof (grub_efi_file_path_device_path_t) * 2);
  if (! file_path)
    return 0;

  grub_memcpy (file_path, dp, size);

  /* Fill the file path for the directory.  */
  d = (grub_efi_device_path_t *) ((char *) file_path
				  + ((char *) d - (char *) dp));
  grub_efi_print_device_path (d);
  copy_file_path ((grub_efi_file_path_device_path_t *) d,
		  dir_start, dir_end - dir_start);

  /* Fill the file path for the file.  */
  d = GRUB_EFI_NEXT_DEVICE_PATH (d);
  copy_file_path ((grub_efi_file_path_device_path_t *) d,
		  dir_end + 1, grub_strlen (dir_end + 1));

  /* Fill the end of device path nodes.  */
  d = GRUB_EFI_NEXT_DEVICE_PATH (d);
  d->type = GRUB_EFI_END_DEVICE_PATH_TYPE;
  d->subtype = GRUB_EFI_END_ENTIRE_DEVICE_PATH_SUBTYPE;
  d->length = sizeof (*d);

  return file_path;
}

static grub_efi_tpm2_protocol_t origin_tpm2_protocol;
static grub_efi_uint32_t counter = 0;
static grub_uint8_t g_output_parameter_block[1024] = {0, };

static void dump_pcrs(struct grub_efi_tpm2_protocol * this)
{
  grub_uint8_t input_parameter_block[] = {0x80, 0x01, 0x00, 0x00, 0x00, 0x14, 0x00, 0x00,
    0x01, 0x7e, 0x00, 0x00, 0x00, 0x01, 0x00, 0x04, 0x03, 0x00, 0x00, 0x00};
  grub_uint32_t input_parameter_size = sizeof(input_parameter_block);
  grub_uint32_t output_parameter_size = sizeof(g_output_parameter_block);
  int i;
  int j;
  grub_uint8_t *pcr_buffer;

  grub_printf("Dump current PCRs!\n");

  for(i = 0 ; i < 24 ; i++)
  {
      grub_memset(input_parameter_block + 17, 0, 3);
      input_parameter_block[17 + (i / 8)] = 0x01 << (i % 8);

      efi_call_5(origin_tpm2_protocol.submit_command, this, input_parameter_size,
        input_parameter_block, output_parameter_size, g_output_parameter_block);

      grub_printf("PCR [%d]: ", i);
      pcr_buffer = (grub_uint8_t*) (g_output_parameter_block + 0x1E);
      for(j = 0 ; j < 20 ; j++)
      {
        grub_printf("%02x ", pcr_buffer[j]);
      }
      grub_printf("\n");
  }
}
grub_efi_status_t hook_get_capability (struct grub_efi_tpm2_protocol *this,
          EFI_TCG2_BOOT_SERVICE_CAPABILITY *protocol_capability)
{
  grub_efi_status_t ret = 0;
  grub_printf("[%d] tpm2_get_capability is called\n", counter++);
  ret = efi_call_2(origin_tpm2_protocol.get_capability, this, protocol_capability);
  grub_printf("    [*] ProtocolCapability = %p\n", protocol_capability);
  hexdump(0, (void*)protocol_capability, sizeof(EFI_TCG2_BOOT_SERVICE_CAPABILITY));
  dump_pcrs(this);
  grub_getkey ();
  return ret;
}

grub_efi_status_t hook_get_event_log (struct grub_efi_tpm2_protocol *this,
          EFI_TCG2_EVENT_LOG_FORMAT event_log_format,
          grub_efi_physical_address_t *event_log_location,
          grub_efi_physical_address_t *event_log_last_entry,
          grub_uint8_t *EventLogTruncated)
{
  grub_efi_status_t ret;
  grub_printf("[%d] tpm2_get_event_log is called, Skip this...\n", counter++);
  ret = efi_call_5(origin_tpm2_protocol.get_event_log, this, event_log_format,
    event_log_location, event_log_last_entry, EventLogTruncated);
  grub_getkey ();
  return ret;
}

grub_efi_status_t hook_hash_log_extend_event (struct grub_efi_tpm2_protocol *this,
          grub_uint64_t flags,
          grub_efi_physical_address_t data_to_hash,
          grub_uint64_t data_to_hashlen,
          EFI_TCG2_EVENT *efi_tcg_event)
{
  grub_efi_status_t ret;
  grub_printf("[%d] tpm2_hash_log_extend_event is called\n", counter++);
  ret = efi_call_5(origin_tpm2_protocol.hash_log_extend_event, this, flags, data_to_hash,
    data_to_hashlen, efi_tcg_event);

  grub_printf("    [*] flags = %lx, data_to_hash = %p, Length = %ld\n",
    flags, (void*) data_to_hash, data_to_hashlen);
  //hexdump(0, (void*) data_to_hash, data_to_hashlen);

  //grub_printf("    [*] efi_tcg_event = %p\n", efi_tcg_event);
  //hexdump(0, (void*) efi_tcg_event, sizeof(EFI_TCG2_EVENT));

  grub_getkey ();
  return ret;
}

grub_efi_status_t hook_submit_command (struct grub_efi_tpm2_protocol *this,
          grub_uint32_t input_parameter_block_size,
          grub_uint8_t *input_parameter_block,
          grub_uint32_t output_parameter_block_size,
          grub_uint8_t *outupt_parameter_block)
{
  grub_efi_status_t ret;
  grub_printf("[%d] tpm2_submit_command is called\n", counter++);
  ret = efi_call_5(origin_tpm2_protocol.submit_command, this, input_parameter_block_size,
    input_parameter_block, output_parameter_block_size, outupt_parameter_block);

  grub_printf("    [*] InputBuffer = %p, InputSize = %d\n", input_parameter_block,
    input_parameter_block_size);
  hexdump(0, (void*) input_parameter_block, input_parameter_block_size);
  grub_printf("    [*] OutputBuffer = %p, OutputSize = %d\n", outupt_parameter_block,
    output_parameter_block_size);
  hexdump(0, (void*) outupt_parameter_block, output_parameter_block_size);

  if ((input_parameter_block[8] == 0x01) && (input_parameter_block[9] == 0x7F))
  {
    grub_printf("TPM2_PolicyPCR is detected\n");
    dump_pcrs(this);
  }

  grub_getkey ();
  return ret;
}

/*
 * Hook the TPM pointer of UEFI service.
 */
static void grub_hook_tpm_ptr(void)
{
  grub_efi_guid_t guid = EFI_TPM2_GUID;
  grub_efi_tpm2_protocol_t *tpm;
  grub_efi_loaded_image_t *image;

  image = grub_efi_get_loaded_image (grub_efi_image_handle);

  tpm = grub_efi_locate_protocol(&guid, NULL);
  grub_printf("BitLeaker: grub_cmd_chainloader is called\n");
  grub_printf("Parent Hande = %p\n", image->parent_handle);
  grub_printf("load_options = %p\n", image->load_options);
  grub_printf("load_options = %s\n", (char*)image->load_options);
  grub_printf("load_options_size = %d\n", image->load_options_size);

  grub_printf("TPM2 service ptr = %p\n", tpm);
  grub_printf("get_capability = %p\n", tpm->get_capability);
  grub_printf("get_active_pcr_blanks = %p\n", tpm->get_active_pcr_blanks);
  grub_printf("get_event_log = %p\n", tpm->get_event_log);
  grub_printf("get_result_of_set_active_pcr_banks = %p\n", tpm->get_result_of_set_active_pcr_banks);
  grub_printf("hash_log_extend_event = %p\n", tpm->hash_log_extend_event);
  grub_printf("submit_command = %p\n", tpm->submit_command);
  grub_printf("Hook start!\n");

  grub_memcpy(&origin_tpm2_protocol, tpm, sizeof(origin_tpm2_protocol));

  /* Hook functions! */
  tpm->get_capability = efi_unwrap_2_get_capability;
  tpm->get_event_log = (void*)efi_unwrap_5_get_event_log;
  tpm->hash_log_extend_event = efi_unwrap_5_hash_log_extend_event;
  tpm->submit_command = efi_unwrap_5_submit_command;

  grub_printf("get_capability = 0x%p\n", tpm->get_capability);
  grub_printf("get_event_log = 0x%p\n", tpm->get_event_log);
  grub_printf("hash_log_extend_event = 0x%p\n", tpm->hash_log_extend_event);
  grub_printf("submit_command = 0x%p\n", tpm->submit_command);
  grub_printf("Hook complete!\n");

  grub_getkey ();
}

static grub_err_t
grub_cmd_chainloader (grub_command_t cmd __attribute__ ((unused)),
		      int argc, char *argv[])
{
  grub_file_t file = 0;
  grub_ssize_t size;
  grub_efi_status_t status;
  grub_efi_boot_services_t *b;
  grub_device_t dev = 0;
  grub_efi_device_path_t *dp = 0;
  grub_efi_loaded_image_t *loaded_image;
  char *filename;
  void *boot_image = 0;
  grub_efi_handle_t dev_handle = 0;

  if (argc == 0)
    return grub_error (GRUB_ERR_BAD_ARGUMENT, N_("filename expected"));
  filename = argv[0];

  /* Hook the TPM pointer. */
  grub_hook_tpm_ptr();

  grub_dl_ref (my_mod);

  /* Initialize some global variables.  */
  address = 0;
  image_handle = 0;
  file_path = 0;

  b = grub_efi_system_table->boot_services;

  file = grub_file_open (filename);
  if (! file)
    goto fail;

  /* Get the root device's device path.  */
  dev = grub_device_open (0);
  if (! dev)
    goto fail;

  if (dev->disk)
    dev_handle = grub_efidisk_get_device_handle (dev->disk);
  else if (dev->net && dev->net->server)
    {
      grub_net_network_level_address_t addr;
      struct grub_net_network_level_interface *inf;
      grub_net_network_level_address_t gateway;
      grub_err_t err;

      err = grub_net_resolve_address (dev->net->server, &addr);
      if (err)
	goto fail;

      err = grub_net_route_address (addr, &gateway, &inf);
      if (err)
	goto fail;

      dev_handle = grub_efinet_get_device_handle (inf->card);
    }

  if (dev_handle)
    dp = grub_efi_get_device_path (dev_handle);

  if (! dp)
    {
      grub_error (GRUB_ERR_BAD_DEVICE, "not a valid root device");
      goto fail;
    }

  file_path = make_file_path (dp, filename);
  if (! file_path)
    goto fail;

  grub_printf ("file path: ");
  grub_efi_print_device_path (file_path);

  size = grub_file_size (file);
  if (!size)
    {
      grub_error (GRUB_ERR_BAD_OS, N_("premature end of file %s"),
		  filename);
      goto fail;
    }
  pages = (((grub_efi_uintn_t) size + ((1 << 12) - 1)) >> 12);

  status = efi_call_4 (b->allocate_pages, GRUB_EFI_ALLOCATE_ANY_PAGES,
			      GRUB_EFI_LOADER_CODE,
			      pages, &address);
  if (status != GRUB_EFI_SUCCESS)
    {
      grub_dprintf ("chain", "Failed to allocate %u pages\n",
		    (unsigned int) pages);
      grub_error (GRUB_ERR_OUT_OF_MEMORY, N_("out of memory"));
      goto fail;
    }

  boot_image = (void *) ((grub_addr_t) address);
  if (grub_file_read (file, boot_image, size) != size)
    {
      if (grub_errno == GRUB_ERR_NONE)
	grub_error (GRUB_ERR_BAD_OS, N_("premature end of file %s"),
		    filename);

      goto fail;
    }

#if defined (__i386__) || defined (__x86_64__)
  if (size >= (grub_ssize_t) sizeof (struct grub_macho_fat_header))
    {
      struct grub_macho_fat_header *head = boot_image;
      if (head->magic
	  == grub_cpu_to_le32_compile_time (GRUB_MACHO_FAT_EFI_MAGIC))
	{
	  grub_uint32_t i;
	  struct grub_macho_fat_arch *archs
	    = (struct grub_macho_fat_arch *) (head + 1);
	  for (i = 0; i < grub_cpu_to_le32 (head->nfat_arch); i++)
	    {
	      if (GRUB_MACHO_CPUTYPE_IS_HOST_CURRENT (archs[i].cputype))
		break;
	    }
	  if (i == grub_cpu_to_le32 (head->nfat_arch))
	    {
	      grub_error (GRUB_ERR_BAD_OS, "no compatible arch found");
	      goto fail;
	    }
	  if (grub_cpu_to_le32 (archs[i].offset)
	      > ~grub_cpu_to_le32 (archs[i].size)
	      || grub_cpu_to_le32 (archs[i].offset)
	      + grub_cpu_to_le32 (archs[i].size)
	      > (grub_size_t) size)
	    {
	      grub_error (GRUB_ERR_BAD_OS, N_("premature end of file %s"),
			  filename);
	      goto fail;
	    }
	  boot_image = (char *) boot_image + grub_cpu_to_le32 (archs[i].offset);
	  size = grub_cpu_to_le32 (archs[i].size);
	}
    }
#endif

  status = efi_call_6 (b->load_image, 0, grub_efi_image_handle, file_path,
		       boot_image, size,
		       &image_handle);
  if (status != GRUB_EFI_SUCCESS)
    {
      if (status == GRUB_EFI_OUT_OF_RESOURCES)
	grub_error (GRUB_ERR_OUT_OF_MEMORY, "out of resources");
      else
	grub_error (GRUB_ERR_BAD_OS, "cannot load image");

      goto fail;
    }

  /* LoadImage does not set a device handler when the image is
     loaded from memory, so it is necessary to set it explicitly here.
     This is a mess.  */
  loaded_image = grub_efi_get_loaded_image (image_handle);
  if (! loaded_image)
    {
      grub_error (GRUB_ERR_BAD_OS, "no loaded image available");
      goto fail;
    }
  loaded_image->device_handle = dev_handle;

  if (argc > 1)
    {
      int i, len;
      grub_efi_char16_t *p16;

      for (i = 1, len = 0; i < argc; i++)
        len += grub_strlen (argv[i]) + 1;

      len *= sizeof (grub_efi_char16_t);
      cmdline = p16 = grub_malloc (len);
      if (! cmdline)
        goto fail;

      for (i = 1; i < argc; i++)
        {
          char *p8;

          p8 = argv[i];
          while (*p8)
            *(p16++) = *(p8++);

          *(p16++) = ' ';
        }
      *(--p16) = 0;

      loaded_image->load_options = cmdline;
      loaded_image->load_options_size = len;
    }

  grub_file_close (file);
  grub_device_close (dev);

  grub_loader_set (grub_chainloader_boot, grub_chainloader_unload, 0);
  return 0;

 fail:

  if (dev)
    grub_device_close (dev);

  if (file)
    grub_file_close (file);

  grub_free (file_path);

  if (address)
    efi_call_2 (b->free_pages, address, pages);

  grub_dl_unref (my_mod);

  return grub_errno;
}

static grub_command_t cmd;

GRUB_MOD_INIT(chainloader)
{
  cmd = grub_register_command ("chainloader", grub_cmd_chainloader,
			       0, N_("Load another boot loader."));
  my_mod = mod;
}

GRUB_MOD_FINI(chainloader)
{
  grub_unregister_command (cmd);
}
