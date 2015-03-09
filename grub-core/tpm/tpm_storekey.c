#include <grub/types.h>
#include <grub/misc.h>
#include <grub/mm.h>
#include <tss/tss.h>

static STORED_KEY *storage = 0;

void InitStorageKey(void) {
	storage = 0;
}

void ClearStorageKey(void) {
	STORED_KEY *cur = storage;
	STORED_KEY *prev = 0;
	
	while(cur) {
		prev = cur;
		cur = cur->next;
		
		grub_free(prev);
	}
}

void ListStoredKey(void) {
	STORED_KEY *cur = storage;
	
	grub_printf("Loaded keys :\n");
	
	while(cur) {
		grub_printf("\t%08x : %s\n", cur->handle, cur->name);
		cur = cur->next;
	}
}

TPM_KEY_HANDLE GetStoredKey(char *name) {
	STORED_KEY *cur = storage;

	if(grub_strncmp(name, "SRK", grub_strlen("SRK")) == 0) {
		return TPM_KH_SRK;
	}

	while(cur) {
		if(grub_memcmp(cur->name, name, grub_strlen((char *) cur->name)) == 0 && grub_strlen(name) == grub_strlen((char *) cur->name))
			return cur->handle;
		cur = cur->next;
	}

	return 0;
}

void AddKey(TPM_KEY_HANDLE handle, char *name) {
	if(storage == 0) {
		storage = grub_malloc(sizeof(STORED_KEY));
		storage->handle = handle;
		grub_memcpy(storage->name, name, sizeof(storage->name));
		storage->next = 0;
	} else {
		STORED_KEY *cur = storage;
		
		storage = grub_malloc(sizeof(STORED_KEY));
		storage->handle = handle;
		grub_memcpy(storage->name, name, sizeof(storage->name));
		storage->next = cur;
	}
}

void RemoveKey(TPM_KEY_HANDLE handle) {
	STORED_KEY *cur = storage;
	STORED_KEY *prev = 0;
	
	while(cur) {
		if(cur->handle == handle) {
			if(prev) {
				prev->next = cur->next;
				grub_free(cur);
			} else {
				storage = cur->next;
				grub_free(cur);
			}
		}
		
		prev = cur;
		cur = cur->next;
	}
}

