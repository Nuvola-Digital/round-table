import "../styles/globals.css";
import type { AppProps } from "next/app";
import {
  ConfigContext,
  config,
  isMainnet,
  defaultGraphQLURI,
} from "../cardano/config";
import Head from "next/head";
import {
  NotificationContext,
  useNotification,
} from "../components/notification";
import { ApolloClient, ApolloProvider, InMemoryCache } from "@apollo/client";
import { useCallback, useEffect, useMemo, useState } from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";


function MyApp({ Component, pageProps }: AppProps) {
  const queryClient = new QueryClient();
  const notification = useNotification();
  const title = useMemo(
    () => (isMainnet(config) ? "RoundTable" : `RoundTable ${config.network}`),
    []
  );
  const configContext = useState(config);

  return (
    <ConfigContext.Provider value={configContext}>
      <QueryClientProvider client={queryClient}>
          <NotificationContext.Provider value={notification}>
              <Head>
                <title>{title}</title>
              </Head>
              <Component {...pageProps} />
          </NotificationContext.Provider>
      </QueryClientProvider>
    </ConfigContext.Provider>
  );
}

export default MyApp;
