use std::io;

use futures::{SinkExt, StreamExt};
use serde_json::Value;
use tokio::{
    io::{AsyncBufRead, AsyncBufReadExt, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader},
    sync::mpsc,
};
use tower::Service;
use tower_lsp::{
    LspService,
    jsonrpc::{Request, Response},
};
use vibeguard_lsp::Backend;

#[tokio::main]
async fn main() {
    if let Err(error) = serve_stdio().await {
        eprintln!("VibeGuard Native L1 stdio transport stopped: {error}");
    }
}

async fn serve_stdio() -> io::Result<()> {
    let (service, socket) = LspService::new(Backend::new);
    let (mut server_requests, mut client_responses) = socket.split();
    let (outbound_tx, mut outbound_rx) = mpsc::channel::<Value>(64);
    let server_request_tx = outbound_tx.clone();
    let server_request_task = tokio::spawn(async move {
        while let Some(request) = server_requests.next().await {
            let Ok(message) = serde_json::to_value(request) else {
                continue;
            };
            if server_request_tx.send(message).await.is_err() {
                return;
            }
        }
    });

    let output_task = tokio::spawn(async move {
        let mut stdout = tokio::io::stdout();
        while let Some(message) = outbound_rx.recv().await {
            write_lsp_message(&mut stdout, &message).await?;
        }
        Ok::<(), io::Error>(())
    });

    let stdin = tokio::io::stdin();
    let mut input = BufReader::new(stdin);
    let mut service = service;
    while let Some(message) = read_lsp_message(&mut input).await? {
        if message.get("method").is_some() {
            let request = serde_json::from_value::<Request>(message).map_err(invalid_data)?;
            let should_exit = request.method() == "exit";
            if std::future::poll_fn(|cx| service.poll_ready(cx))
                .await
                .is_err()
            {
                break;
            }
            let response = service.call(request).await.map_err(invalid_data)?;
            if let Some(response) = response {
                send_response(&outbound_tx, response).await?;
            }
            if should_exit {
                break;
            }
        } else {
            let response = serde_json::from_value::<Response>(message).map_err(invalid_data)?;
            if client_responses.send(response).await.is_err() {
                break;
            }
        }
    }

    drop(outbound_tx);
    server_request_task.abort();
    let _ = server_request_task.await;
    match output_task.await {
        Ok(result) => result,
        Err(error) => Err(io::Error::other(error)),
    }
}

async fn send_response(sender: &mpsc::Sender<Value>, response: Response) -> io::Result<()> {
    let message = serde_json::to_value(response).map_err(invalid_data)?;
    sender.send(message).await.map_err(|_| {
        io::Error::new(
            io::ErrorKind::BrokenPipe,
            "VibeGuard Native L1 output transport is unavailable",
        )
    })
}

async fn read_lsp_message<R>(input: &mut R) -> io::Result<Option<Value>>
where
    R: AsyncBufRead + Unpin,
{
    const MAX_HEADER_BYTES: usize = 16 * 1024;
    const MAX_MESSAGE_BYTES: usize = 16 * 1024 * 1024;

    let mut content_length = None;
    let mut header_bytes = 0;
    loop {
        let mut line = Vec::new();
        let read = input.read_until(b'\n', &mut line).await?;
        if read == 0 {
            return if header_bytes == 0 {
                Ok(None)
            } else {
                Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "LSP stream ended in message headers",
                ))
            };
        }
        header_bytes += read;
        if header_bytes > MAX_HEADER_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "LSP message headers exceed the supported size",
            ));
        }
        if line == b"\n" || line == b"\r\n" {
            break;
        }
        let line = std::str::from_utf8(&line).map_err(invalid_data)?;
        let Some((name, value)) = line.trim_end().split_once(':') else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "LSP header is missing a colon",
            ));
        };
        if name.trim().eq_ignore_ascii_case("Content-Length") {
            content_length = Some(value.trim().parse::<usize>().map_err(invalid_data)?);
        }
    }

    let content_length = content_length.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "LSP message is missing Content-Length",
        )
    })?;
    if content_length > MAX_MESSAGE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "LSP message exceeds the supported size",
        ));
    }
    let mut body = vec![0_u8; content_length];
    input.read_exact(&mut body).await?;
    serde_json::from_slice(&body)
        .map(Some)
        .map_err(invalid_data)
}

async fn write_lsp_message<W>(output: &mut W, message: &Value) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let body = serde_json::to_vec(message).map_err(invalid_data)?;
    output
        .write_all(format!("Content-Length: {}\r\n\r\n", body.len()).as_bytes())
        .await?;
    output.write_all(&body).await?;
    output.flush().await
}

fn invalid_data(error: impl std::error::Error + Send + Sync + 'static) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    #[tokio::test]
    async fn reads_case_insensitive_lsp_content_length_headers() {
        let expected = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "exit"
        });
        let body = serde_json::to_vec(&expected).expect("the fixture should serialize");
        let (mut writer, reader) = tokio::io::duplex(1024);
        writer
            .write_all(format!("content-length: {}\r\n\r\n", body.len()).as_bytes())
            .await
            .expect("the header should write");
        writer
            .write_all(&body)
            .await
            .expect("the body should write");
        drop(writer);

        let mut reader = BufReader::new(reader);
        let actual = read_lsp_message(&mut reader)
            .await
            .expect("the frame should parse")
            .expect("the frame should contain a message");
        assert_eq!(actual, expected);
    }

    #[tokio::test]
    async fn writes_complete_lsp_frames_without_waiting_for_stream_close() {
        let message = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": { "ready": true }
        });
        let body = serde_json::to_vec(&message).expect("the fixture should serialize");
        let header = format!("Content-Length: {}\r\n\r\n", body.len());
        let (mut writer, mut reader) = tokio::io::duplex(1024);

        write_lsp_message(&mut writer, &message)
            .await
            .expect("the frame should write and flush");
        let mut actual = vec![0_u8; header.len() + body.len()];
        reader
            .read_exact(&mut actual)
            .await
            .expect("the flushed frame should be readable before stream close");
        assert_eq!(actual, [header.as_bytes(), body.as_slice()].concat());
    }
}
