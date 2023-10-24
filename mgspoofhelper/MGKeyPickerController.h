#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>

@interface MGKeyPickerController : UITableViewController {
	NSMutableArray *selectedItems;
	NSArray<NSArray *> *allKeys;
}
@end