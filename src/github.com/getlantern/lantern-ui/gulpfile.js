/*global require */
(function () {
  'use strict';
  var console = require('console');
  var gulp = require('gulp');
  var util = require('gulp-util');
  var compass = require('gulp-compass');
  var usemin = require('gulp-usemin');
  var uglify = require('gulp-uglify');
  var minifyHtml = require('gulp-minify-html');
  var minifyCss = require('gulp-minify-css');
  var rev = require('gulp-rev');
  var ngConfig = require('gulp-ng-config');
  var protractor = require("gulp-protractor");
  var del = require('del');
  var fs = require('fs');
  var raml_mock = require('raml-mocker-server');
  var bs = require('browser-sync').create();
  var ws = require('ws').Server;


  var scssGlob = 'app/scss/*.scss';
  var lanternBackendPort = 3031;
  var lanternBackend = 'http://localhost:' + lanternBackendPort;
  var mockProApiPort = 3032;
  var mockProApi = 'http://localhost:' + mockProApiPort;

  gulp.task('compass', function() {
    gulp.src(scssGlob)
    .pipe(compass({
      config_file: 'config/compass.rb',
      css: 'app/_css'
    }));
  });

  gulp.task('usemin', ['compass', 'dist-env', 'clean'], function () {
    return gulp.src('app/index.html')
    .pipe(usemin({
      css: [minifyCss(), 'concat', rev()],
      html: [minifyHtml({empty: true, conditionals: true})],
      libjs: [rev()],
      js: [uglify(), rev()]
    }))
    .pipe(gulp.dest('dist/'));
  });

  gulp.task('copy', ['clean'], function () {
    gulp.src('app/font/*')
    .pipe(gulp.dest('dist/font'));
    gulp.src('app/locale/*')
    .pipe(gulp.dest('dist/locale'));
    gulp.src('app/img/**/*')
    .pipe(gulp.dest('dist/img'));
    gulp.src('app/partials/*')
    .pipe(gulp.dest('dist/partials'));
  });

  gulp.task('clean', function (cb) {
    del(['dist/'], cb);
  });

  gulp.task('build', ['usemin', 'copy'], function() {
    // place code for your default task here
  });

  gulp.task('mock', function() {
    fs.access('pro-spec', function(err) {
      if (err) {
        util.log('please `ln -s` pro-spec folder first!');
      } else {
        util.log('Starting mock pro server at localhost:', mockProApiPort);
        raml_mock({
          path: "pro-spec",
          port: mockProApiPort,
          debug: true,
          watch: true
        });
      }
    });
  });

  gulp.task('dev-env', function() {
    gulp.src('config/env.json')
    .pipe(ngConfig('app.constants', {
      environment: 'dev',
      createModule: false,
      constants: {
        "PRO_API": mockProApi
      }
    }))
    .pipe(gulp.dest('app/js/'));
  });

  gulp.task('dist-env', function() {
    gulp.src('config/env.json')
    .pipe(ngConfig('app.constants', {
      environment: 'dist',
      createModule: false
    }))
    .pipe(gulp.dest('app/js/'));
  });

  gulp.task('watchScss', function() {
    //watch .scss files
    gulp.watch(scssGlob, ['compass']);
  });

  gulp.task('ws', function() {
    util.log('Starting mock Lantern backend (WebSocket) at ' + lanternBackend + '/data');
    ws({port: lanternBackendPort, path: '/data'}).on('connection', function(ws) {
      ws.on('message', function(message) {
        util.log('Lantern backend received: %s', message);
      });
      ws.send(JSON.stringify({Type: "mocked"}));
    });
  });

  // Use browser-sync to proxy websocket to mock lantern backend and serve
  // static files at same time (sacrificed livereload ability).
  gulp.task('server', ['ws', 'watchScss'], function() {
    bs.init({
      proxy: {
        target: lanternBackend,
        ws: true
      },
      serveStatic: ['.', 'app']
    });
  });

  gulp.task('test-server', ['ws', 'watchScss'], function() {
    bs.init({
      proxy: {
        target: lanternBackend,
        ws: true
      },
      open: false,
      serveStatic: ['.', 'app']
    });
  });

  gulp.task('dist-server', ['dist-env', 'ws', 'watchScss'], function() {
    bs.init({
      proxy: {
        target: lanternBackend,
        ws: true
      },
      serveStatic: ['.', 'dist']
    });
  });

  gulp.task('webdriver_update', protractor.webdriver_update);

  gulp.task('run-test', ['test-server', 'webdriver_update'], function() {
    var completion = gulp.src(["features/*.feature"])
    .pipe(protractor.protractor({
      configFile: "config/protractor.conf.js"
    }));
    return completion;
  });

  gulp.task('test', ['run-test'], function() {
    bs.exit();
  });

  gulp.task('default', ['server', 'dev-env', 'mock'], function() {
    // place code for your default task here
  });

}());
