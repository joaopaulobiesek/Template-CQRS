using Azure.Storage.Blobs;
using Template.Application.Common.Interfaces.Services;
using Template.Application.Common.Models;
using Template.Application.ViewModels.Storage;
using Microsoft.AspNetCore.Http;

namespace Template.Infra.ExternalServices.Storage;

internal class AzureStorage : IStorage
{
    private readonly BlobContainerClient _client;

    public AzureStorage(BlobContainerClient client)
    {
        _client = client;
    }

    public async Task<ApiResponse<UploadFileVM>> UploadFile(IFormFile file, CancellationToken cancellationToken)
    {
        var fileName = Guid.NewGuid();
        var fileExtension = Path.GetExtension(file.FileName);
        var fullFileName = $"{fileName}{fileExtension}";
        try
        {
            var blob = _client.GetBlobClient(fullFileName);
            var response = await blob.UploadAsync(file.OpenReadStream(), cancellationToken);

            if (response.GetRawResponse().Status == 201)
                return new SucessoResponse<UploadFileVM>("201", new UploadFileVM(fullFileName, _client.Uri.AbsoluteUri + "/" + fullFileName));
        }
        catch (Exception ex)
        {
            return new ErroResponse<UploadFileVM>(ex.Message);
        }
        return new SucessoResponse<UploadFileVM>(string.Empty);
    }

    public async Task<ApiResponse<UploadFileVM>> DeleteFile(string fileName)
    {
        try
        {
            var blob = _client.GetBlobClient(fileName);
            var response = await blob.DeleteIfExistsAsync();
            if (response.Value)
                return new SucessoResponse<UploadFileVM>("Deletado com sucesso!");
            else
                return new ErroResponse<UploadFileVM>("Arquivo não encontrado!");

        }
        catch (Exception ex)
        {
            return new ErroResponse<UploadFileVM>(ex.Message);
        }
    }

    public async Task<ApiResponse<byte[]>> DownloadFile(string fileName)
    {
        try
        {
            var blob = _client.GetBlobClient(fileName);
            var response = await blob.DownloadAsync();

            if (response.GetRawResponse().Status == 200)
            {
                using var memoryStream = new MemoryStream();
                await response.Value.Content.CopyToAsync(memoryStream);
                var content = memoryStream.ToArray();
                return new SucessoResponse<byte[]>("Download efetuado com sucesso.", content);
            }
            else
            {
                return new ErroResponse<byte[]>("Não foi possível baixar o arquivo.");
            }
        }
        catch (Exception ex)
        {
            return new ErroResponse<byte[]>(ex.Message);
        }
    }
}