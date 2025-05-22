#include <minix/drivers.h>
#include <minix/driver.h>
#include <stdio.h>
#include <stdlib.h>
#include <minix/ds.h>
#include <sys/socket.h>
#include <sys/ucred.h>
#include "secret.h"

/*
 * Function prototypes for the secret driver.
 */
FORWARD _PROTOTYPE( char * secret_name,   (void) );
FORWARD _PROTOTYPE( int secret_open,      (struct driver *d, message *m) );
FORWARD _PROTOTYPE( int secret_close,     (struct driver *d, message *m) );
/*
FORWARD _PROTOTYPE( struct device * secret_prepare, (int device) );
*/
FORWARD _PROTOTYPE( int secret_transfer,  (int procnr, int opcode,
                                          u64_t position, iovec_t *iov,
                                          unsigned nr_req) );
/*
FORWARD _PROTOTYPE( void nop_geometry, (struct partition *entry) );
*/

/* SEF functions and variables. */
FORWARD _PROTOTYPE( void sef_local_startup, (void) );
FORWARD _PROTOTYPE( int sef_cb_init, (int type, sef_init_info_t *info) );
FORWARD _PROTOTYPE( int sef_cb_lu_state_save, (int) );
FORWARD _PROTOTYPE( int lu_state_restore, (void) );

/* Entry points to the secret driver. */
PRIVATE struct driver secret_tab =
{
    secret_name,
    secret_open,
    secret_close,
    secret_ioctl,
    nop_prepare,
    secret_transfer,
    nop_cleanup,
    nop_geometry,
    nop_alarm,
    nop_cancel,
    nop_select,
    nop_ioctl,
    do_nop,
};

/** Represents the /dev/secret device. */
PRIVATE struct device secret_device;

PRIVATE struct dev_data secret_data;

PRIVATE char * secret_name(void)
{
    printf("secret_name()\n");
    return "secret";
}

PRIVATE int secret_ioctl(d, m)
    struct driver *d;
    message *m;
{
    /* Verify right message type is passed */
    if (m->m_type != DEV_IOCTL_S) {
        return -EIO;
    }
    int request = m->REQUEST;

    switch (request) {
        case SSGRANT:
            int res;
            uid_t grantee; /* the uid of the new owner of the secret */
            res = sys_safecopyfrom(m->IO_ENDPT, (vir_bytes)m->IO_GRANT, 0, (vir_bytes) &grantee, sizeof(grantee, D));

            if (res == OK) {
                dev_data.owner_uid = grantee;
            }

        default:
            return ENOTTY;
    }

    return res;
}

PRIVATE int secret_open(d, m)
    struct driver *d;
    message *m;
{
    /* Verify right message type is passed */
    if (m->m_type != DEV_OPEN) {
        return -EIO;
    }
    int flags = m->COUNT;

    /* Opening with read and write is not permitted */
    if ((flags & R_BIT) && (flags & W_BIT)) {
        return -EACCES;
    }

    uucred owner; 
    uucred requester;
    int res;
    if (secret == NULL && (flags & W_BIT)) {
        /* Secret is up for grabs by anyone if its empty */
        res = getnucred(m->m_source, &owner); /* Assign the owner */
        if (res != 0) {
            return -EIO;
        } 
        dev_data.owner_uid = owner.uid;
        (dev_data.open_count)++;
        return OK;
    } 

    /* Can only be opened for reading once the secret is owned */
    if (!(flags & R_BIT)) {
        return -ENOSPC;
    }

    res = getnucred(m->m_source, &requester); /* Assign the requester */
    if (res != 0) {
        return -EIO;
    } 

    /* Only the owner can access the secret */
    if (requester.uid != dev_data.owner_uid) {
        return -EACCES;
    }

    (dev_data.open_count)++;
    return OK;
}

PRIVATE int secret_close(d, m)
    struct driver *d;
    message *m;
{
    (dev_data.open_count)--;

    /* Reset buffer once all fd's are closed */
    if (dev_data.open_count == 0) {
        dev_data.secret = NULL;
        dev_data.read_ptr = NULL;
        dev_data.write_ptr = NLUL;
    }

    return OK;
}

/*
PRIVATE struct device * secret_prepare(dev)
    int dev;
{
    secret_device.dv_base.lo = 0;
    secret_device.dv_base.hi = 0;
    secret_device.dv_size.lo = strlen(secret_MESSAGE);
    secret_device.dv_size.hi = 0;
    return &secret_device;
}
*/

PRIVATE int secret_transfer(proc_nr, opcode, position, iov, nr_req)
    int proc_nr;
    int opcode;
    u64_t position;
    iovec_t *iov;
    unsigned nr_req;
{
    int bytes, ret;

    switch (opcode)
    {
        /* Tell the secret up to <bytes> to caller */
        case DEV_GATHER_S:

            /* Takes minimum of requested size and remaining bytes */
            bytes = dev_data.write_pos - dev_data.read_pos > iov->iov_size ?
                iov->iov_size : dev_data.write_pos - dev_data.read_pos;

            if (bytes <= 0) 
            {
                return OK;
            }

            ret = sys_safecopyto(proc_nr, iov->iov_addr, 0,
                                (vir_bytes) (dev_data.secret + dev_data.read_pos),
                                 bytes, D);
            if (ret == OK) {
                iov->iov_size -= bytes;
                dev_data.read_pos += bytes;
            }
            break;

        /* Listen to secret up to <bytes> from caller */
        case DEV_SCATTER_S:
            /* Takes minimum of writing size and remaining bytes */
            bytes = SECRET_SIZE - dev_data.write_pos > iov->iov_size ?
                iov->iov_size : SECRET_SIZE - dev_data.write_pos;

            if (bytes <= 0) 
            {
                return OK;
            }

            ret = sys_safecopyfrom(proc_nr, iov->iov_addr, 0,
                                (vir_bytes) (dev_data.secret + dev_data.write_pos),
                                 bytes, D);

            if (ret == OK) {
                iov->iov_size -= bytes;
                dev_data.write_pos += bytes;
            }
            break;

        default:
            return EINVAL;
    }
    return ret;
}

PRIVATE int sef_cb_lu_state_save(int state) {
/* Save the state. */
    ds_publish_mem("dev_data", &dev_data, sizeof(dev_data), DSF_OVERWRITE);

    return OK;
}

PRIVATE int lu_state_restore() {
/* Restore the state. */
    size_t len = sizeof(dev_data);

    ds_retrieve_mem("dev_data", (char *)&dev_data, &len);
    ds_delete_u32("dev_data");

    return OK;
}

PRIVATE void sef_local_startup()
{
    /*
     * Register init callbacks. Use the same function for all event types
     */
    sef_setcb_init_fresh(sef_cb_init);
    sef_setcb_init_lu(sef_cb_init);
    sef_setcb_init_restart(sef_cb_init);

    /*
     * Register live update callbacks.
     */
    /* - Agree to update immediately when LU is requested in a valid state. */
    sef_setcb_lu_prepare(sef_cb_lu_prepare_always_ready);
    /* - Support live update starting from any standard state. */
    sef_setcb_lu_state_isvalid(sef_cb_lu_state_isvalid_standard);
    /* - Register a custom routine to save the state. */
    sef_setcb_lu_state_save(sef_cb_lu_state_save);

    /* Let SEF perform startup. */
    sef_startup();
}

PRIVATE int sef_cb_init(int type, sef_init_info_t *info)
{
/* Initialize the secret driver. */
    int do_announce_driver = TRUE;

    switch(type) {
        case SEF_INIT_FRESH:
            /* Secret is initially NULL */
            dev_data.secret = NULL;
            dev_data.read_pos = 0;
            dev_data.write_pos = 0;
            dev_data.open_count = 0;
        break;

        case SEF_INIT_LU:
            /* Restore the state. */
            lu_state_restore();
            do_announce_driver = FALSE;

            printf("Hey, I'm a new version!\n");
        break;

        case SEF_INIT_RESTART:
            /* A restart resets the state of secret to be empty */
            dev_data.secret = NULL;
            dev_data.read_pos = 0;
            dev_data.write_pos = 0;
            dev_data.open_count = 0;
            printf("Hey, I've just been restarted!\n");
        break;
    }

    /* Announce we are up when necessary. */
    if (do_announce_driver) {
        driver_announce();
    }

    /* Initialization completed successfully. */
    return OK;
}

PUBLIC int main(int argc, char **argv)
{
    /*
     * Perform initialization.
     */
    sef_local_startup();

    /*
     * Run the main loop.
     */
    driver_task(&secret_tab, DRIVER_STD);
    return OK;
}

