//
//  Copyright (c) 2008 Cédric Luthi
//

#import <CoreFoundation/CFBundle.h>
#import <Foundation/NSString.h>
#import <Foundation/NSException.h>
#import <mach/mach_init.h>
#import <mach/vm_map.h>
#import <mach-o/dyld.h>
#import <mach-o/getsect.h>
#import <mach-o/nlist.h>


@interface QuietXcode : NSObject {}
@end

@implementation QuietXcode

+ (void) patch
{
	unsigned char *auto_collect_internal = NULL, *dyld_stub_malloc_printf = NULL;
	uint32_t i, count = _dyld_image_count();
	
	CFBundleRef mainBundle = CFBundleGetMainBundle();
	CFStringRef bundleIdentifier = CFBundleGetIdentifier(mainBundle);
	if (bundleIdentifier && CFStringCompare(bundleIdentifier, CFSTR("com.apple.Xcode"), 0) != kCFCompareEqualTo) {
		// Only patch when main executable is Xcode
		return;
	}
	
	// Check Xcode version number, only patch for version 3.1 (1099), 3.1.1 (1115) and 3.1.2 (1149)
	CFStringRef versionNumber = CFBundleGetValueForInfoDictionaryKey(mainBundle, kCFBundleVersionKey);
	float floatVersion = [(NSString *)versionNumber floatValue];
	if (!versionNumber) {
		// This happens when using xcodebuild for example
		return;
	} else if (!(floatVersion == 1099 || floatVersion == 1115 || floatVersion == 1149)) {
		@throw [NSException exceptionWithName:nil reason:[NSString stringWithFormat:@"untested Xcode version %@ (%@)", CFBundleGetValueForInfoDictionaryKey(mainBundle, CFSTR("CFBundleShortVersionString")), versionNumber] userInfo:nil];
	}
	
	// Search for the libauto dylib
	for(i = 0; i < count; i++) {
		const char* imageName = _dyld_get_image_name(i);
		if (strstr(imageName, "libauto")) {
			const struct mach_header *imageHeader = _dyld_get_image_header(i);
			
			// Find the address of the private symbol auto_collect_internal(Auto::Zone*, int)
			struct nlist symlist[] = {{"__Z21auto_collect_internalPN4Auto4ZoneEi", 0, 0, 0, 0}, NULL};
			if (nlist(imageName, symlist) == 0 && symlist[0].n_value != 0) {
				auto_collect_internal = (unsigned char*)((int)imageHeader + symlist[0].n_value);
			}
			
			// address of the dyld_stub_malloc_printf jmp
			// 0xAA is computed by running otool -Iv /usr/lib/libauto.dylib
			/* Indirect symbols for (__IMPORT,__jump_table) 86 entries
			   address    index name
			   0x0002d080   517 _NSAddImage
			   ...
			   0x0002d12a   554 _malloc_printf
			   
			   => 0x0002d12a - 0x0002d080 = 0xAA
			 */
			uint32_t size = 0;
			dyld_stub_malloc_printf = (unsigned char*)(getsectdatafromheader(imageHeader, SEG_IMPORT, "__jump_table", &size) + 0xAA);
			break;
		}
	}
	
	if (auto_collect_internal == NULL) {
		@throw [NSException exceptionWithName:nil reason:@"auto_collect_internal function not found" userInfo:nil];
	}
	
	const unsigned char *malloc_printf_call = auto_collect_internal + 3687; // call site (offset in the auto_collect_internal function)
	char malloc_printf_call_instructions[] = {0xe8, 0xFF, 0xFF, 0xFF, 0xFF}; // expected instruction at call site (computed below)
	// Compute the offset from the call site to dyld_stub_malloc_printf
	*(int*)(malloc_printf_call_instructions+1) = dyld_stub_malloc_printf - malloc_printf_call - sizeof(malloc_printf_call_instructions);
	
	// Check that we are nop'ing the "call" instruction we are supposed to patch
	if (memcmp(malloc_printf_call, malloc_printf_call_instructions, sizeof(malloc_printf_call_instructions)) == 0) {
		// Make it writable in order not to crash in the memset (EXC_BAD_ACCESS)
		kern_return_t vm_err = vm_protect(mach_task_self(), (vm_address_t)malloc_printf_call, sizeof(malloc_printf_call_instructions), false, VM_PROT_ALL);
		if (vm_err != KERN_SUCCESS) {
			@throw [NSException exceptionWithName:nil reason:[NSString stringWithFormat:@"vm_protect error (%d)", vm_err] userInfo:nil];
		} else {
			// nop the call to malloc_printf
			memset((void *)malloc_printf_call, 0x90, sizeof(malloc_printf_call_instructions));
			NSLog(@"<QuietXcode> loaded successfully");
		}
	} else {
		@throw [NSException exceptionWithName:nil reason:@"unexpected auto_collect_internal function" userInfo:nil];
	}
}

+ (void) initialize
{
	@try {
		[self patch];
	} @catch (NSException *exception) {
		NSLog(@"<QuietXcode> failed to load: %@", [exception reason]);
	}
}

@end
