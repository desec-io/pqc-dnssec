<template>
  <v-app>
    <v-app-bar
      app
      color="primary"
      dark
    >

      <v-spacer></v-spacer>

      <v-btn
        href="https://indico.dns-oarc.net/event/42/contributions/902/"
        target="_blank"
        text
      >
        <span class="mr-2">Talk at OARC 37</span>
        <v-icon>mdi-open-in-new</v-icon>
      </v-btn>
      <v-btn
        href="https://dnsviz.net/d/falcon.example.pq-dnssec.dedyn.io/dnssec/"
        target="_blank"
        text
      >
        <span class="mr-2">FALCON-512 Test Zone on DNSViz</span>
        <v-icon>mdi-open-in-new</v-icon>
      </v-btn>
      <v-btn
        href="https://github.com/nils-wisiol/dns-falcon/"
        target="_blank"
        text
      >
        <span class="mr-2">Code on GitHub</span>
        <v-icon>mdi-open-in-new</v-icon>
      </v-btn>
    </v-app-bar>

    <v-main>
      <HelloWorld/>
    </v-main>
  </v-app>
</template>

<script>
import HelloWorld from './components/HelloWorld';

export default {
  name: 'App',

  components: {
    HelloWorld,
  },

  data: () => ({
    //
  }),
};
</script>
