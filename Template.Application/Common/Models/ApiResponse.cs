namespace Template.Application.Common.Models;

public abstract class ApiResponse<T> where T : notnull
{
    public bool Sucesso { get; set; }
    public string Mensagem { get; set; }
    public T? Dados { get; set; }

    protected ApiResponse(bool sucesso, string mensagem, T? dados)
    {
        Sucesso = sucesso;
        Mensagem = mensagem;
        Dados = dados;
    }
}

public class SucessoResponse<T> : ApiResponse<T> where T : notnull
{
    public SucessoResponse(string mensagem, T? dados = default) : base(true, mensagem, dados)
    {
    }
}

public class ErroResponse<T> : ApiResponse<T> where T : notnull
{
    public int StatusCode { get; }
    public ICollection<NotificationError>? Erros { get; private set; }

    public ErroResponse(string mensagem, int statusCode = 400, T? dados = default, ICollection<NotificationError>? erros = null) : base(false, mensagem, dados)
    {
        StatusCode = statusCode;
        Erros = erros;
    }

    public void AddError(string key, string message)
    {
        Erros ??= new List<NotificationError>();
        Erros.Add(new NotificationError(key, message));
    }
}

public class NotificationError
{
    public string Key { get; set; }

    public string Message { get; set; }

    public NotificationError()
    {
    }

    public NotificationError(string key, string message)
    {
        Key = key;
        Message = message;
    }
}