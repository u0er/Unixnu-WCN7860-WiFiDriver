/* SPDX-License-Identifier: GPL-2.0-only */
/* IO80211.framework's ioctl fallback and SystemConfiguration discovery,
 * following HackiOS RedwoodWLAN's registry contract. The data interface
 * and Apple80211 operations are owned by PeachNet, not this registry node. */
#include <pexpert/arm64/board_config.h>
#include <sys/errno.h>
#if defined(PANDORA)
#include <IOKit/IOLib.h>
#include <IOKit/IOKitKeys.h>
#include <IOKit/IOPlatformExpert.h>
#include <IOKit/IOService.h>
#include <IOKit/IOUserClient.h>
#include <kern/thread.h>
#include <libkern/c++/OSData.h>
#include <libkern/c++/OSKext.h>
#include <pexpert/pexpert.h>
#include <sys/proc.h>

/* The existing Nezha identity service defines this base in
 * SweetPlatformExpert.cpp. Keep one metaclass definition in the kernel. */
class IONetworkController : public IOService {
    OSDeclareDefaultStructors(IONetworkController);
};
class IO80211Controller : public IONetworkController {
    OSDeclareDefaultStructors(IO80211Controller);
};
class IONetworkInterface : public IOService {
    OSDeclareDefaultStructors(IONetworkInterface);
};
OSDefineMetaClassAndStructors(IO80211Controller, IONetworkController);
OSDefineMetaClassAndStructors(IONetworkInterface, IOService);

/* InterfaceNamer must open this service before it publishes registry quiet.
 * Without it SCNetworkInterfaceCopyAll blocks wifid and then SpringBoard.
 * BSD already assigned en0, so there is no interface naming operation here.
 * See HackiOS MiniIONetworkStack.cpp. */
class IONetworkStack : public IOService {
    OSDeclareDefaultStructors(IONetworkStack);
};
class IONetworkStackUserClient : public IOUserClient {
    OSDeclareDefaultStructors(IONetworkStackUserClient);
public:
    virtual bool start(IOService *provider) APPLE_KEXT_OVERRIDE;
    virtual IOReturn clientClose(void) APPLE_KEXT_OVERRIDE;
    virtual IOReturn setProperties(OSObject *) APPLE_KEXT_OVERRIDE;
};
OSDefineMetaClassAndStructors(IONetworkStack, IOService);
OSDefineMetaClassAndStructors(IONetworkStackUserClient, IOUserClient);
/* One delayed snapshot with the existing Wi-Fi diagnostic flag: identify the
 * service blocking InterfaceNamer without changing its busy accounting. */
static void network_quiet_diagnostic(void *, wait_result_t)
{
    IOService *root = IOService::getServiceRoot();
    (void)root->waitQuiet(45000000000ULL);
    IOLog("NEZHA WIFI: registry busy after network discovery %u\n", root->getBusyState());
    OSKext *image4 = OSKext::lookupKextWithIdentifier("com.apple.security.AppleImage4");
    IOLog("NEZHA WIFI: AppleImage4 present %u loaded %u started %u\n",
        image4 != NULL, image4 && image4->isLoaded(), image4 && image4->isStarted());
    OSSafeReleaseNULL(image4);
    IORegistryIterator *iter = IORegistryIterator::iterateOver(root,
        gIOServicePlane, kIORegistryIterateRecursively);
    if (iter) {
        IOService *service;
        while ((service = OSDynamicCast(IOService, iter->getNextObject()))) {
            IOService *provider = service->getProvider();
            if (provider && !strcmp(provider->getName(), "defaults"))
                IOLog("NEZHA WIFI: defaults child %s (%s) state %#x\n", service->getName(),
                    service->getMetaClass()->getClassName(), (unsigned)service->getState());
            if (service->getBusyState())
                IOLog("NEZHA WIFI: busy service %s (%s) count %u\n",
                    service->getName(), service->getMetaClass()->getClassName(),
                    service->getBusyState());
        }
        iter->release();
    }
    thread_terminate(current_thread());
}
bool IONetworkStackUserClient::start(IOService *provider)
{
    if (!IOUserClient::start(provider)) return false;
    char name[32];
    proc_selfname(name, sizeof(name));
    IOLog("NEZHA WIFI: network stack opened by %s, registry busy %u\n",
        name, (unsigned)IOService::getServiceRoot()->getBusyState());
    int capture = 0;
    (void)PE_parse_boot_argn("nezha_wifi_dump", &capture, sizeof(capture));
    thread_t thread;
    if (capture == 1 && kernel_thread_start(network_quiet_diagnostic, NULL, &thread) == KERN_SUCCESS)
        thread_deallocate(thread);
    return true;
}
IOReturn IONetworkStackUserClient::clientClose(void)
{
    if (!isInactive()) terminate();
    return kIOReturnSuccess;
}
IOReturn IONetworkStackUserClient::setProperties(OSObject *)
{ return kIOReturnUnsupported; }
static int network_stack_publish(void)
{
    IOService *resources = IOService::getResourceService();
    IONetworkStack *stack = new IONetworkStack;
    if (!resources || !stack || !stack->init()) {
        OSSafeReleaseNULL(stack); return ENOMEM;
    }
    stack->setName("IONetworkStack");
    stack->setProperty(kIOUserClientClassKey, "IONetworkStackUserClient");
    int error = EIO;
    if (stack->attach(resources)) {
        if (stack->start(resources)) {
            stack->registerService(); error = 0;
        } else stack->detach(resources);
    }
    stack->release(); return error;
}
extern "C" int peach_wlan_publish(const char *, const unsigned char *);
extern "C" int peach_wlan_publish(const char *name, const unsigned char *mac)
{
    int stack_error = network_stack_publish();
    if (stack_error) return stack_error;
    IOService *provider = IOService::getPlatform();
    IO80211Controller *controller = new IO80211Controller;
    IONetworkInterface *interface = new IONetworkInterface;
    OSData *address = OSData::withBytes(mac, 6);
    if (!provider || !controller || !interface || !address || !controller->init() || !interface->init()) {
        OSSafeReleaseNULL(controller); OSSafeReleaseNULL(interface); OSSafeReleaseNULL(address);
        return ENOMEM;
    }
    controller->setName("NezhaPeachWLAN");
    controller->setProperty("IOMACAddress", address);
    controller->setProperty("IOBuiltin", true);
    address->release();
    interface->setName("NezhaPeachInterface");
    interface->setProperty("IOInterfaceName", name);
    interface->setProperty("BSD Name", name);
    interface->setProperty("IOInterfaceNamePrefix", "en");
    interface->setProperty("IOInterfaceType", 6ULL, 32);
    interface->setProperty("IOInterfaceUnit", 0ULL, 32);
    interface->setProperty("IOBuiltin", true);
    interface->setProperty("IOPrimaryInterface", true);
    interface->setProperty("IO80211InterfaceRole", "Infrastructure");
    int error = EIO;
    if (controller->attach(provider)) {
        if (controller->start(provider)) {
            if (interface->attach(controller)) {
                if (interface->start(controller)) {
                    controller->registerService(); interface->registerService();
                    IOLog("NEZHA WIFI: Apple80211 ioctl interface %s published (link separate)\n", name);
                    error = 0;
                } else interface->detach(controller);
            }
            if (error) controller->stop(provider);
        }
        if (error) controller->detach(provider);
    }
    interface->release(); controller->release(); return error;
}
#else
extern "C" int peach_wlan_publish(const char *, const unsigned char *) { return EOPNOTSUPP; }
#endif
