using Template.Application.Common.Models;
using Microsoft.AspNetCore.Mvc;

namespace Template.Api.Controllers.System;

public abstract class BaseController : ControllerBase
{
    protected IActionResult HandleResponse<T>(ApiResponse<T> response) where T : class
    {
        if (response.Sucesso)
            return Ok(response);

        if (response is ErroResponse<T> erroResponse)
            return StatusCode(erroResponse.StatusCode, erroResponse);

        return BadRequest(response);
    }
}