#import <Foundation/Foundation.h>

#ifdef __cplusplus
extern "C" {
#endif

NSDictionary *key_mapping_table();
NSString *deobfuscate_key(NSString *obfuscatedKey, NSDictionary *keyTable);

#ifdef __cplusplus
}
#endif
