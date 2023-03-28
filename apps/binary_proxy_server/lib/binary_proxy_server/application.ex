defmodule BinaryProxyServer.Application do
  use Application

  @impl true
  def start(_type, _args) do
    port = String.to_integer(System.get_env("PORT") || "80")

    children = [
      {Task.Supervisor, name: BinaryProxyServer.TaskSupervisor},
      Supervisor.child_spec({Task, fn -> BinaryProxyServer.accept(port) end}, restart: :permanent)
    ]

    opts = [strategy: :one_for_one, name: BinaryProxyServer.Supervisor]
    Supervisor.start_link(children, opts)
  end
end
