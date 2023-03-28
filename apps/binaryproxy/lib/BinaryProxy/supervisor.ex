defmodule BinaryProxy.Supervisor do
    use Supervisor
  
    def start_link(opts) do
      Supervisor.start_link(__MODULE__, :ok, opts)
    end
  
    @impl true
    def init(:ok) do
      children = [
        {DynamicSupervisor, name: BinaryProxy.BucketSupervisor, strategy: :one_for_one},
        {BinaryProxy.Registry, name: BinaryProxy.Registry},
      ]
  
      Supervisor.init(children, strategy: :one_for_all)
    end
  end