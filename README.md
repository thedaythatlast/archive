main.cpp:
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <authz.h>
#include <sddl.h>

#include <iomanip>
#include <iostream>
#include <string>
#include <vector>

#pragma comment(lib, "Authz.lib")
#pragma comment(lib, "Advapi32.lib")

namespace
{
    // Arbitrary, structurally valid package SIDs for this controlled Authz test.
    //
    // These do not need to correspond to installed packages because
    // AUTHZ_SKIP_TOKEN_GROUPS permits an arbitrary/application-specific SID.
    constexpr wchar_t kPackageSid1[] =
        L"S-1-15-2-100-101-102-103-104-105-106-107";

    constexpr wchar_t kPackageSid2[] =
        L"S-1-15-2-200-201-202-203-204-205-206-207";

    // Built-in internetClient capability SID.
    constexpr wchar_t kCapabilitySid[] =
        L"S-1-15-3-1";

    // A private access bit used only by this repro.
    constexpr ACCESS_MASK kTestAccess = 0x00000001;

    [[noreturn]] void Fail(const wchar_t* operation, DWORD error)
    {
        std::wcerr << L"FATAL: " << operation
                   << L" failed; GetLastError=" << error
                   << L" (0x" << std::hex << error << std::dec << L")\n";
        ExitProcess(error == ERROR_SUCCESS ? 1 : error);
    }

    class LocalMemory
    {
    public:
        LocalMemory() = default;
        explicit LocalMemory(void* p) : pointer_(p) {}

        ~LocalMemory()
        {
            if (pointer_ != nullptr)
            {
                LocalFree(pointer_);
            }
        }

        LocalMemory(const LocalMemory&) = delete;
        LocalMemory& operator=(const LocalMemory&) = delete;

        LocalMemory(LocalMemory&& other) noexcept
            : pointer_(other.pointer_)
        {
            other.pointer_ = nullptr;
        }

        LocalMemory& operator=(LocalMemory&& other) noexcept
        {
            if (this != &other)
            {
                if (pointer_ != nullptr)
                {
                    LocalFree(pointer_);
                }

                pointer_ = other.pointer_;
                other.pointer_ = nullptr;
            }

            return *this;
        }

        void* get() const
        {
            return pointer_;
        }

    private:
        void* pointer_ = nullptr;
    };

    class AuthzContext
    {
    public:
        AuthzContext() = default;

        explicit AuthzContext(AUTHZ_CLIENT_CONTEXT_HANDLE handle)
            : handle_(handle)
        {
        }

        ~AuthzContext()
        {
            if (handle_ != nullptr)
            {
                AuthzFreeContext(handle_);
            }
        }

        AuthzContext(const AuthzContext&) = delete;
        AuthzContext& operator=(const AuthzContext&) = delete;

        AuthzContext(AuthzContext&& other) noexcept
            : handle_(other.handle_)
        {
            other.handle_ = nullptr;
        }

        AuthzContext& operator=(AuthzContext&& other) noexcept
        {
            if (this != &other)
            {
                if (handle_ != nullptr)
                {
                    AuthzFreeContext(handle_);
                }

                handle_ = other.handle_;
                other.handle_ = nullptr;
            }

            return *this;
        }

        AUTHZ_CLIENT_CONTEXT_HANDLE get() const
        {
            return handle_;
        }

    private:
        AUTHZ_CLIENT_CONTEXT_HANDLE handle_ = nullptr;
    };

    class AuthzResourceManager
    {
    public:
        AuthzResourceManager()
        {
            if (!AuthzInitializeResourceManager(
                    AUTHZ_RM_FLAG_NO_AUDIT,
                    nullptr,
                    nullptr,
                    nullptr,
                    L"PackageCapabilitySidRepro",
                    &handle_))
            {
                Fail(L"AuthzInitializeResourceManager", GetLastError());
            }
        }

        ~AuthzResourceManager()
        {
            if (handle_ != nullptr)
            {
                AuthzFreeResourceManager(handle_);
            }
        }

        AuthzResourceManager(const AuthzResourceManager&) = delete;
        AuthzResourceManager& operator=(const AuthzResourceManager&) = delete;

        AUTHZ_RESOURCE_MANAGER_HANDLE get() const
        {
            return handle_;
        }

    private:
        AUTHZ_RESOURCE_MANAGER_HANDLE handle_ = nullptr;
    };

    LocalMemory SidFromString(const wchar_t* stringSid)
    {
        PSID sid = nullptr;

        if (!ConvertStringSidToSidW(stringSid, &sid))
        {
            Fail(L"ConvertStringSidToSidW", GetLastError());
        }

        if (!IsValidSid(sid))
        {
            Fail(L"IsValidSid", ERROR_INVALID_SID);
        }

        return LocalMemory(sid);
    }

    LocalMemory SecurityDescriptorForSid(const wchar_t* stringSid)
{
    // Both descriptors have the same owner, group, DACL flags,
    // access mask, and ACE type. Only the ACE trustee SID differs.
    const std::wstring sddl =
        std::wstring(L"O:SYG:SYD:P(A;;0x1;;;") +
        stringSid +
        L")";

    PSECURITY_DESCRIPTOR sd = nullptr;

    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.c_str(),
            SDDL_REVISION_1,
            &sd,
            nullptr))
    {
        Fail(
            L"ConvertStringSecurityDescriptorToSecurityDescriptorW",
            GetLastError());
    }

    if (!IsValidSecurityDescriptor(sd))
    {
        LocalFree(sd);
        Fail(
            L"IsValidSecurityDescriptor",
            ERROR_INVALID_SECURITY_DESCR);
    }

    return LocalMemory(sd);
}

    AuthzContext ContextFromSingleSid(
        AUTHZ_RESOURCE_MANAGER_HANDLE resourceManager,
        PSID sid)
    {
        AUTHZ_CLIENT_CONTEXT_HANDLE context = nullptr;
        LUID identifier{};

        // AUTHZ_SKIP_TOKEN_GROUPS makes this a controlled context containing
        // the supplied SID, without account/group expansion.
        if (!AuthzInitializeContextFromSid(
                AUTHZ_SKIP_TOKEN_GROUPS,
                sid,
                resourceManager,
                nullptr,
                identifier,
                nullptr,
                &context))
        {
            Fail(L"AuthzInitializeContextFromSid", GetLastError());
        }

        return AuthzContext(context);
    }

    AuthzContext AddEnabledSid(
        AUTHZ_CLIENT_CONTEXT_HANDLE originalContext,
        PSID sid)
    {
        SID_AND_ATTRIBUTES addedSid{};
        addedSid.Sid = sid;
        addedSid.Attributes = SE_GROUP_ENABLED;

        AUTHZ_CLIENT_CONTEXT_HANDLE newContext = nullptr;

        if (!AuthzAddSidsToContext(
                originalContext,
                &addedSid,
                1,
                nullptr,
                0,
                &newContext))
        {
            Fail(L"AuthzAddSidsToContext", GetLastError());
        }

        return AuthzContext(newContext);
    }

    struct CheckResult
    {
        bool apiSucceeded = false;
        ACCESS_MASK grantedAccess = 0;
        DWORD error = ERROR_SUCCESS;
    };

    CheckResult CheckAccess(
        AUTHZ_CLIENT_CONTEXT_HANDLE context,
        PSECURITY_DESCRIPTOR securityDescriptor)
    {
        AUTHZ_ACCESS_REQUEST request{};
        request.DesiredAccess = kTestAccess;
        request.PrincipalSelfSid = nullptr;
        request.ObjectTypeList = nullptr;
        request.ObjectTypeListLength = 0;
        request.OptionalArguments = nullptr;

        ACCESS_MASK grantedAccess = 0;
        DWORD replyError = ERROR_SUCCESS;

        AUTHZ_ACCESS_REPLY reply{};
        reply.ResultListLength = 1;
        reply.GrantedAccessMask = &grantedAccess;
        reply.SaclEvaluationResults = nullptr;
        reply.Error = &replyError;

        SetLastError(ERROR_SUCCESS);

        const BOOL ok = AuthzAccessCheck(
            0,
            context,
            &request,
            nullptr,
            securityDescriptor,
            nullptr,
            0,
            &reply,
            nullptr);

        if (!ok)
        {
            return {
                false,
                0,
                GetLastError()
            };
        }

        return {
            true,
            grantedAccess,
            replyError
        };
    }

    std::wstring FormatResult(const CheckResult& result)
    {
        wchar_t buffer[96]{};

        if (!result.apiSucceeded)
        {
            swprintf_s(
                buffer,
                L"API-FAIL/error=%lu",
                result.error);
        }
        else
        {
            swprintf_s(
                buffer,
                L"0x%08lX/error=%lu",
                static_cast<unsigned long>(result.grantedAccess),
                result.error);
        }

        return buffer;
    }

    struct ContextRow
    {
        const wchar_t* name;
        AUTHZ_CLIENT_CONTEXT_HANDLE context;
    };
}

int wmain()
{
    AuthzResourceManager resourceManager;

    auto packageSid1 = SidFromString(kPackageSid1);
    auto packageSid2 = SidFromString(kPackageSid2);
    auto capabilitySid = SidFromString(kCapabilitySid);

    auto packageAceSd = SecurityDescriptorForSid(kPackageSid1);
    auto capabilityAceSd = SecurityDescriptorForSid(kCapabilitySid);

    // 1. Package SID only.
    auto packageOnly = ContextFromSingleSid(
        resourceManager.get(),
        static_cast<PSID>(packageSid1.get()));

    // 2. Capability SID only.
    auto capabilityOnly = ContextFromSingleSid(
        resourceManager.get(),
        static_cast<PSID>(capabilitySid.get()));

    // 3. Package SID + capability SID.
    auto packageBaseForCombined = ContextFromSingleSid(
        resourceManager.get(),
        static_cast<PSID>(packageSid1.get()));

    auto packageAndCapability = AddEnabledSid(
        packageBaseForCombined.get(),
        static_cast<PSID>(capabilitySid.get()));

    // 4. A different package SID + the same capability SID.
    auto differentPackageBase = ContextFromSingleSid(
        resourceManager.get(),
        static_cast<PSID>(packageSid2.get()));

    auto differentPackageAndCapability = AddEnabledSid(
        differentPackageBase.get(),
        static_cast<PSID>(capabilitySid.get()));

    const std::vector<ContextRow> rows{
        {L"package only", packageOnly.get()},
        {L"capability only", capabilityOnly.get()},
        {L"package + capability", packageAndCapability.get()},
        {L"different package + capability",
         differentPackageAndCapability.get()}
    };

    std::wcout
        << L"Package SID 1 : " << kPackageSid1 << L"\n"
        << L"Package SID 2 : " << kPackageSid2 << L"\n"
        << L"Capability SID: " << kCapabilitySid << L"\n"
        << L"Desired access: 0x00000001\n\n";

    std::wcout
        << std::left
        << std::setw(34) << L"context"
        << std::setw(30) << L"package-ACE SD"
        << L"capability-ACE SD\n";

    std::wcout
        << std::wstring(94, L'-')
        << L"\n";

    for (const auto& row : rows)
    {
        const CheckResult packageResult = CheckAccess(
            row.context,
            static_cast<PSECURITY_DESCRIPTOR>(packageAceSd.get()));

        const CheckResult capabilityResult = CheckAccess(
            row.context,
            static_cast<PSECURITY_DESCRIPTOR>(capabilityAceSd.get()));

        std::wcout
            << std::left
            << std::setw(34) << row.name
            << std::setw(30) << FormatResult(packageResult)
            << FormatResult(capabilityResult)
            << L"\n";
    }

    return 0;
}

cmakelists.txt:
cmake_minimum_required(VERSION 3.20)
project(authz_package_capability_repro LANGUAGES CXX)

add_executable(authz_package_capability_repro main.cpp)

target_compile_features(
    authz_package_capability_repro
    PRIVATE cxx_std_17
)

target_compile_definitions(
    authz_package_capability_repro
    PRIVATE UNICODE _UNICODE
)

target_link_libraries(
    authz_package_capability_repro
    PRIVATE Authz Advapi32
)

PS C:\Users\nguyen\reproAC\build\Debug> ."C:/Users/nguyen/reproAC/build/Debug/authz_package_capability_repro.exe"
Package SID 1 : S-1-15-2-100-101-102-103-104-105-106-107
Package SID 2 : S-1-15-2-200-201-202-203-204-205-206-207
Capability SID: S-1-15-3-1
Desired access: 0x00000001

context                           package-ACE SD                capability-ACE SD
----------------------------------------------------------------------------------------------
package only                      0x00000001/error=0            0x00000000/error=5
capability only                   0x00000000/error=5            0x00000001/error=0
package + capability              0x00000001/error=0            0x00000001/error=0
different package + capability    0x00000000/error=5            0x00000001/error=0
PS C:\Users\nguyen\reproAC\build\Debug> 
