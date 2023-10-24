#import <substrate.h>
#import <stdint.h>
#import <sys/utsname.h>
#import <sys/sysctl.h>

#import <Foundation/Foundation.h>
#import "capstone/capstone.h"
#import <Cephei/Cephei.h>
#import "mapping.h"
#import <HBLog.h>

static NSDictionary *modifiedKeys;
static NSArray *appsChosen;
static NSDictionary *keyTable;

static CFTypeRef (*orig_MGCopyAnswer)(CFStringRef property, uint32_t *outTypeCode);
CFTypeRef new_MGCopyAnswer(CFStringRef property, uint32_t *outTypeCode){
    NSString *deobfuscatedKey = deobfuscate_key((__bridge NSString *)property, keyTable);
    if (deobfuscatedKey && modifiedKeys[deobfuscatedKey]) {
        HBLogDebug(@"deobfuscatedKey: %@, property: %@, ret: %@", deobfuscatedKey, property, modifiedKeys[deobfuscatedKey]);
        return (__bridge_retained CFStringRef)modifiedKeys[deobfuscatedKey];
    }
    CFTypeRef ret = orig_MGCopyAnswer(property, outTypeCode);
    HBLogDebug(@"property: %@, ret: %@", property, ret);
    return ret;
}

int uname(struct utsname *);
%hookf(int, uname, struct utsname *value) {
    int ret = %orig;
    
    if (value){
        if (modifiedKeys[@"ProductType"]) {
            NSString *productType = modifiedKeys[@"ProductType"];
            const char *machine = productType.UTF8String;
            strcpy(value->machine, machine);
        }
        
        if (modifiedKeys[@"UserAssignedDeviceName"] || modifiedKeys[@"ComputerName"]) {
            NSString *computerName = modifiedKeys[@"ComputerName"] ?: modifiedKeys[@"UserAssignedDeviceName"];
            const char *nname = computerName.UTF8String;
            strcpy(value->nodename, nname);
        }
    }
    
    HBLogDebug(@"utsmachine: %s, utsrelease: %s, utssystem: %s, utsnodename: %s", value->machine, value->release, value->version, value->nodename);
    
    return ret;
}

int sysctlbyname(const char *, void *, size_t *, void *, size_t);
%hookf(int, sysctlbyname, const char *name, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    int ret = %orig;
    
    if(strcmp(name, "hw.machine") == 0 && oldp){
        if (modifiedKeys[@"ProductType"]) {
            const char *machine = ((NSString *)modifiedKeys[@"ProductType"]).UTF8String;
            strcpy((char *)oldp, machine);
        }
    } else if(strcmp(name, "kern.osproductversion") == 0 && oldp){
        if (modifiedKeys[@"ProductVersion"]) {
            const char *version = ((NSString *)modifiedKeys[@"ProductVersion"]).UTF8String;
            strcpy((char *)oldp, version);
        }
    } else if(strcmp(name, "kern.osversion") == 0 && oldp){
        if (modifiedKeys[@"BuildVersion"]) {
            const char *buildversion = ((NSString *)modifiedKeys[@"BuildVersion"]).UTF8String;
            strcpy((char *)oldp, buildversion);
        }
    }
    
    return ret;
}

int sysctl(int *, u_int , void *, size_t *, void *, size_t);
%hookf(int, sysctl, int *name, u_int namelen, void *oldp, size_t *oldlenp, const void *newp, size_t newlen) {
    int ret = %orig;
    
    if (namelen == 2 && name[0] == CTL_HW && name[1] == HW_MACHINE && oldp) {
        NSString *productTypeK = keyTable[@"ProductType"] ?: @"ProductType";
        if (modifiedKeys[productTypeK]) {
            const char *machine = ((NSString *)modifiedKeys[productTypeK]).UTF8String;
            strncpy((char*)oldp, machine, strlen(machine));
        }
    }
    return ret;
}

static void appsChosenUpdated() {
    appsChosen = [[[HBPreferences alloc] initWithIdentifier:@"com.tonyk7.MGSpoofHelperPrefsSuite"] objectForKey:@"spoofApps"];
}

static void modifiedKeyUpdated() {
    modifiedKeys = [[[HBPreferences alloc] initWithIdentifier:@"com.tonyk7.MGSpoofHelperPrefsSuite"] objectForKey:@"modifiedKeys"];
}

static void initkeyTable() {
    keyTable = key_mapping_table();
}

// Taken from https://mayuyu.io/2017/06/26/HookingMGCopyAnswerLikeABoss/
%ctor {
    @autoreleasepool {
        appsChosenUpdated();
        // don't do anything if we in an app we don't want to spoof anything
        if (![appsChosen containsObject:[NSBundle mainBundle].bundleIdentifier])
            return;
        
        // basically dlopen libMobileGestalt
        MSImageRef libGestalt = MSGetImageByName("/usr/lib/libMobileGestalt.dylib");
        
        if (libGestalt) {
            
            // Get "_MGCopyAnswer" symbol
            void *MGCopyAnswerFn = MSFindSymbol(libGestalt, "_MGCopyAnswer");
            
            csh handle;
            cs_insn *insn;
            cs_insn BLInstruction;
            size_t count;
            unsigned long realMGAddress=0;
            //MSHookFunction(Symbol,(void*)new_MGCA, (void**)&old_MGCA);
            if (cs_open(CS_ARCH_ARM64, CS_MODE_ARM, &handle) == CS_ERR_OK) {
                /*cs_disasm(csh handle,
                 const uint8_t *code, size_t code_size,
                 uint64_t address,
                 size_t count,
                 cs_insn **insn);*/
                count=cs_disasm(handle, (const uint8_t *)MGCopyAnswerFn ,0x1000, (uint64_t)MGCopyAnswerFn, 0, &insn);
                if (count > 0) {
                    // HBLogDebug(@"Found %lu instructions",count);
                    for (size_t j = 0; j < count; j++) {
                        // HBLogDebug(@"0x%" PRIx64 ":\t%s\t\t%s\n", insn[j].address, insn[j].mnemonic,insn[j].op_str);
                        if (insn[j].id == ARM64_INS_B){
                            BLInstruction = insn[j];
                            sscanf(BLInstruction.op_str, "#%lx", &realMGAddress);
                            HBLogDebug(@"realMGAddress: 0x%lx", realMGAddress);
                            break;
                        }
                    }
                    cs_free(insn, count);
                } else{
                    HBLogDebug(@"ERROR: Failed to disassemble given code!%i \n",cs_errno(handle));
                }
                
                
                cs_close(&handle);
                
                //Now perform actual hook
                MSHookFunction((void*)realMGAddress,(void*)new_MGCopyAnswer, (void**)&orig_MGCopyAnswer);
            } else {
                HBLogDebug(@"MGHooker: CSE Failed");
            }
        }
        
        CFNotificationCenterAddObserver(CFNotificationCenterGetDarwinNotifyCenter(), NULL, (CFNotificationCallback)appsChosenUpdated, CFSTR("com.tonyk7.mgspoof/appsChosenUpdated"), NULL, CFNotificationSuspensionBehaviorDeliverImmediately);
        CFNotificationCenterAddObserver(CFNotificationCenterGetDarwinNotifyCenter(), NULL, (CFNotificationCallback)modifiedKeyUpdated, CFSTR("com.tonyk7.mgspoof/modifiedKeyUpdated"), NULL, CFNotificationSuspensionBehaviorDeliverImmediately);
        modifiedKeyUpdated();
        initkeyTable();
    }
}
