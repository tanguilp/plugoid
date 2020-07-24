defmodule Plugoid.MixProject do
  use Mix.Project

  def project do
    [
      app: :plugoid,
      description: "OpenID Connect Plug for Phoenix",
      version: "0.3.0",
      elixir: "~> 1.9",
      compilers: [:phoenix] ++ Mix.compilers,
      start_permanent: Mix.env() == :prod,
      docs: [
        main: "readme",
        extras: ["README.md", "QUICKSTART.md"]
      ],
      deps: deps(),
      package: package(),
      source_url: "https://github.com/tanguilp/plugoid"
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger]
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:dialyxir, "~> 1.0.0-rc.4", only: [:dev], runtime: false},
      {:ex_doc, "~> 0.19", only: :dev, runtime: false},
      {:jason, "~> 1.1"},
      {:jwks_uri_updater, "~> 1.1"},
      {:oauth2_metadata_updater, "~> 1.2"},
      {:oauth2_utils, "~> 0.1"},
      {:oidc, "~> 0.3"},
      {:phoenix_html, "~> 2.0"},
      {:phoenix, "~> 1.0"}
    ]
  end

  def package() do
    [
      licenses: ["Apache-2.0"],
      links: %{"GitHub" => "https://github.com/tanguilp/plugoid"}
    ]
  end
end
