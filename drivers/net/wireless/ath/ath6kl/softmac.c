/*
 * Copyright (c) 2011 Atheros Communications Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include "core.h"
#include "debug.h"
#include <linux/vmalloc.h>
#define MAC_FILE "ath6k/AR6003/hw2.1.1/softmac"

typedef char            A_CHAR;
extern int android_readwrite_file(const A_CHAR *filename, A_CHAR *rbuf, const A_CHAR *wbuf, size_t length);

/* Bleh, same offsets. */
#define AR6003_MAC_ADDRESS_OFFSET 0x16
#define AR6004_MAC_ADDRESS_OFFSET 0x16

/* Global variables, sane coding be damned. */
u8 *ath6kl_softmac;
size_t ath6kl_softmac_len;

#if 1 //def FEATURE_SKY_WLAN
char *softmac_file = "/dev/panmac";
#define ATH_SOFT_MAC_TMP_BUF_LEN            64
#define ATH_MAC_LEN             6               /* length of mac in bytes */
#endif

static void ath6kl_calculate_crc(u32 target_type, u8 *data, size_t len)
{
	u16 *crc, *data_idx;
	u16 checksum;
	int i;

	if (target_type == TARGET_TYPE_AR6003) {
		crc = (u16 *)(data + 0x04);
	} else if (target_type == TARGET_TYPE_AR6004) {
		len = 1024;
		crc = (u16 *)(data + 0x04);
	} else {
		ath6kl_err("Invalid target type\n");
		return;
	}

	ath6kl_dbg(ATH6KL_DBG_BOOT, "Old Checksum: %u\n", *crc);

	*crc = 0;
	checksum = 0;
	data_idx = (u16 *)data;

	for (i = 0; i < len; i += 2) {
		checksum = checksum ^ (*data_idx);
		data_idx++;
	}

	*crc = cpu_to_le16(checksum);

	ath6kl_dbg(ATH6KL_DBG_BOOT, "New Checksum: %u\n", checksum);
}

#ifdef CONFIG_MACH_MSM8X60_PORORO
/* soft mac FEATURE_SKY_WLAN */
static int wmic_ether_aton(const char *orig, size_t len, u8 *eth)
{
  const char *bufp;
  int i;

  i = 0;
  for(bufp = orig; bufp!=orig+len && *bufp; ++bufp) {
    unsigned int val;
    unsigned char c = *bufp++;
    if (c >= '0' && c <= '9') val = c - '0';
    else if (c >= 'a' && c <= 'f') val = c - 'a' + 10;
    else if (c >= 'A' && c <= 'F') val = c - 'A' + 10;
    else {
        printk("%s: MAC value is invalid\n", __FUNCTION__);
        break;
    }

    val <<= 4;
    c = *bufp++;
    if (c >= '0' && c <= '9') val |= c - '0';
    else if (c >= 'a' && c <= 'f') val |= c - 'a' + 10;
    else if (c >= 'A' && c <= 'F') val |= c - 'A' + 10;
    else {
        printk("%s: MAC value is invalid\n", __FUNCTION__);
        break;
    }

    eth[i] = (unsigned char) (val & 0377);
    if(++i == ATH_MAC_LEN) {
        return 1;
    }
    if (*bufp != ':')
        break;
  }
  return 0;
}

static int read_mac_addr_from_file(const char *p_mac_file, char *mac_addr)
{
        mm_segment_t        oldfs;
        struct file     *filp;
        struct inode        *inode = NULL;
        int         length;
        unsigned char soft_mac_tmp_buf[ATH_SOFT_MAC_TMP_BUF_LEN];
        /* open file */
        oldfs = get_fs();
        set_fs(KERNEL_DS);
        filp = filp_open(p_mac_file, O_RDONLY, S_IRUSR);

      
        printk("%s try to open file %s\n", __FUNCTION__, p_mac_file);

        if (IS_ERR(filp)) {
            printk("%s: file %s filp_open error\n", __FUNCTION__, p_mac_file);
            set_fs(oldfs);
        return -1;
        }

        if (!filp->f_op) {
            printk("%s: File Operation Method Error\n", __FUNCTION__);
            filp_close(filp, NULL);
            set_fs(oldfs);
        return -1;
        }

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,20)
        inode = filp->f_path.dentry->d_inode;
#else
        inode = filp->f_dentry->d_inode;
#endif
        if (!inode) {
            printk("%s: Get inode from filp failed\n", __FUNCTION__);
            filp_close(filp, NULL);
            set_fs(oldfs);
        return -1;
        }

    printk("%s file offset opsition: %xh\n", __FUNCTION__, (unsigned)filp->f_pos);

        length = filp->f_op->read(filp, soft_mac_tmp_buf, ATH_SOFT_MAC_TMP_BUF_LEN, &filp->f_pos);
        soft_mac_tmp_buf[length] = '\0'; /* ensure that it is NULL terminated */

        /* read data out successfully */
        filp_close(filp, NULL);
        set_fs(oldfs);

        /* convert mac address */
        if (!wmic_ether_aton(soft_mac_tmp_buf, length, mac_addr)) {
            printk("%s: convert mac value fail\n", __FUNCTION__);
        return -1;
        }

    return 0;
}
#else
static int ath6kl_fetch_mac_file(struct ath6kl *ar)
{
	const struct firmware *fw_entry;
	int ret = 0;


	ret = request_firmware(&fw_entry, MAC_FILE, ar->dev);
	if (ret)
		return ret;

	ath6kl_softmac_len = fw_entry->size;
	ath6kl_softmac = kmemdup(fw_entry->data, fw_entry->size, GFP_KERNEL);

	if (ath6kl_softmac == NULL)
		ret = -ENOMEM;

	release_firmware(fw_entry);

	return ret;
}
#endif

void ath6kl_mangle_mac_address(struct ath6kl *ar)
{
	u8 *ptr_mac;
	int i, ret;
#ifdef CONFIG_MACH_MSM8X60_PORORO
//LS3_LeeYoungHo_120424_chg [ 
//	unsigned int softmac[6];
	unsigned char softmac[6];
#endif

	switch (ar->target_type) {
	case TARGET_TYPE_AR6003:
		ptr_mac = ar->fw_board + AR6003_MAC_ADDRESS_OFFSET;
		break;
	case TARGET_TYPE_AR6004:
		ptr_mac = ar->fw_board + AR6004_MAC_ADDRESS_OFFSET;
		break;
	default:
		ath6kl_err("Invalid Target Type\n");
		return;
	}

#ifdef CONFIG_MACH_MSM8X60_PORORO
//LS3_LeeYoungHo_120424_chg [ 
//	ret = ath6kl_fetch_softmac_info(ar);
 ret = read_mac_addr_from_file(softmac_file, softmac);
 if (ret < 0)
 {
  		ath6kl_err("MAC address file not found: panmac read fail\n");
    /* create a random MAC in case we cannot read file from system */
    ptr_mac[0] = 0x2C; /* locally administered */
    ptr_mac[1] = 0x30;
    ptr_mac[2] = 0x68;
    ptr_mac[3] = random32() & 0xff; 
    ptr_mac[4] = random32() & 0xff; 
    ptr_mac[5] = random32() & 0xff;

	ath6kl_dbg(ATH6KL_DBG_BOOT,
			"MAC random generated as %02X:%02X:%02X:%02X:%02X:%02X\n",
			ptr_mac[0], ptr_mac[1], ptr_mac[2],
			ptr_mac[3], ptr_mac[4], ptr_mac[5]);
	}
 else
 {
//panmac read OK
   if (memcmp(softmac, "\0\0\0\0\0\0", 6)!=0) 
   {
      memcpy(ptr_mac, softmac, 6);

    		for (i=0; i<6; ++i) 
    		{
    			ptr_mac[i] = softmac[i] & 0xff;
      }

     	ath6kl_dbg(ATH6KL_DBG_BOOT,
     			"MAC from panmac %02X:%02X:%02X:%02X:%02X:%02X\n",
     			ptr_mac[0], ptr_mac[1], ptr_mac[2],
     			ptr_mac[3], ptr_mac[4], ptr_mac[5]);
   } 
   else 
   {
    		ath6kl_err("panmac is init value\n");
      /* create a random MAC in case we cannot read file from system */
      ptr_mac[0] = 0x2C; /* locally administered */
      ptr_mac[1] = 0x30;
      ptr_mac[2] = 0x68;
      ptr_mac[3] = random32() & 0xff; 
      ptr_mac[4] = random32() & 0xff; 
      ptr_mac[5] = random32() & 0xff;

  	ath6kl_dbg(ATH6KL_DBG_BOOT,
  			"MAC random generated as %02X:%02X:%02X:%02X:%02X:%02X\n",
  			ptr_mac[0], ptr_mac[1], ptr_mac[2],
  			ptr_mac[3], ptr_mac[4], ptr_mac[5]);
  	}
 }

#else
	ret = ath6kl_fetch_mac_file(ar);
	if (ret) {
		ath6kl_err("MAC address file not found\n");
		return;
	}

	for (i = 0; i < ETH_ALEN; ++i) {
	   ptr_mac[i] = ath6kl_softmac[i] & 0xff;
	}

	kfree(ath6kl_softmac);
#endif

	ath6kl_calculate_crc(ar->target_type, ar->fw_board, ar->fw_board_len);
}
