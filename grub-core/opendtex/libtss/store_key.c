#include <opendtex/libtss.h>
#include <grub/crypto.h>

static LIST_ENTRY keys;

void InitStoredKey(void) {
	InitializeListHead(&keys);
}

void ClearStoredKey(void) {
	//TODO  GGX (Unload all keys)
}

void ListStoredKey(void) {
	PLIST_ENTRY entry;
	
	printf("Loaded keys :\n");
	
	for(entry = keys.Flink ; entry != &keys ; entry = entry->Flink) {
		LOADED_KEY * key = CONTAINING_RECORD(entry, LOADED_KEY, entry);
		
		printf("\t%08x : %s\n", key->handle, key->name);
	}
}

TPM_KEY_HANDLE GetKeyHandle(char * name) {
	PLIST_ENTRY entry;

	if(grub_strncmp(name, "SRK", grub_strlen("SRK")) == 0) {
		return TPM_KH_SRK;
	}
	
	for(entry = keys.Flink ; entry != &keys ; entry = entry->Flink) {
		LOADED_KEY * key = CONTAINING_RECORD(entry, LOADED_KEY, entry);
		
		if(grub_strncmp(key->name, name, sizeof(key->name)) == 0) {
			return key->handle;
		}
	}

	return 0;
}

char * GetKeyName(TPM_KEY_HANDLE handle) {
	PLIST_ENTRY entry;

	if(handle == TPM_KH_SRK) {
		return (char *)"SRK";
	}
	
	for(entry = keys.Flink ; entry != &keys ; entry = entry->Flink) {
		LOADED_KEY * key = CONTAINING_RECORD(entry, LOADED_KEY, entry);
		
		if(key->handle == handle) {
			return key->name;
		}
	}

	return 0;
}

void AddKey(TPM_KEY_HANDLE handle, char * name) {
	PLIST_ENTRY entry;
	LOADED_KEY * toInsert;

	if((handle == TPM_KH_SRK) || (grub_strncmp(name, "SRK", grub_strlen("SRK")) == 0)) {
		printf("Error: can't add SRK key\n");
		return;
	}

	for(entry = keys.Flink ; entry != &keys ; entry = entry->Flink) {
		LOADED_KEY * key = CONTAINING_RECORD(entry, LOADED_KEY, entry);
		
		if(key->handle == handle) {
			printf("Error: key handle already in the storage\n");
			return;
		}
		
		if(grub_strncmp(key->name, name, sizeof(key->name)) == 0) {
			printf("Error: key name already in the storage\n");
			return;
		}
	}
	
	toInsert = grub_malloc(sizeof(LOADED_KEY));
	toInsert->handle = handle;
	grub_strncpy(toInsert->name, name, sizeof(toInsert->name));
	
	InsertHeadList(&keys, &toInsert->entry);
}

void RemoveKey(TPM_KEY_HANDLE handle) {
	PLIST_ENTRY entry;
	
	for(entry = keys.Flink ; entry != &keys ; entry = entry->Flink) {
		LOADED_KEY * key = CONTAINING_RECORD(entry, LOADED_KEY, entry);
		
		if(key->handle == handle) {
			RemoveEntryList(entry);
			grub_free(key);
			return;
		}
	}
}

