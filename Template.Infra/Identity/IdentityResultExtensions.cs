using Template.Application.Common.Models;

namespace Template.Infra.Identity;

public static class IdentityResultExtensions
{
    public static ApiResponse<IdentityResult> ToApplicationResult(this IdentityResult result)
    {
        return result.Succeeded
            ? new SucessoResponse<IdentityResult>("", result)
            : new ErroResponse<IdentityResult>("", 400, result, result.Errors.Select(e => new NotificationError(e.Code, e.Description)).ToList());
    }
}