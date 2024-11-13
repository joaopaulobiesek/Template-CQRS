using Template.Application.Common.Behaviours;
using Template.Application.Domains.Identity.Auth.Commands.LoginUser;
using Template.Application.ViewModels.Users;
using Microsoft.AspNetCore.Mvc;

namespace Template.Api.Controllers.Identity.Auth;

[Route("[controller]")]
public class AuthController : ControllerBase
{
    /// <summary>
    /// Responsável por fazer login no sistema.
    /// </summary>
    /// <param name="handler"></param>
    /// <param name="command"></param>
    /// <param name="cancellationToken"></param>
    /// <returns></returns>
    [HttpPost("Login")]
    public async Task<IActionResult> LoginAsync([FromServices] IHandlerBase<LoginUserCommand, LoginUserVm> handler, [FromBody] LoginUserCommand command, CancellationToken cancellationToken)
    {
        var response = await handler.Execute(command, cancellationToken);

        if (!response.Sucesso)
            return BadRequest(response);
        else if (string.IsNullOrEmpty(response.Dados!.Token))
            return Unauthorized();
        else
            return Ok(response);
    }
}