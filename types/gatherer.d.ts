/**
 * @license Copyright 2018 The Lighthouse Authors. All Rights Reserved.
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.
 */

import _NetworkNode = require('../lighthouse-core/lib/dependency-graph/network-node');
import _CPUNode = require('../lighthouse-core/lib/dependency-graph/cpu-node');
import _Simulator = require('../lighthouse-core/lib/dependency-graph/simulator/simulator');
import Driver = require('../lighthouse-core/gather/driver');

declare global {
  module LH.Gatherer {
    /** The Lighthouse wrapper around a raw CDP session. */
    export interface FRProtocolSession {
      hasNextProtocolTimeout(): boolean;
      getNextProtocolTimeout(): number;
      setNextProtocolTimeout(ms: number): void;
      on<TEvent extends keyof LH.CrdpEvents>(event: TEvent, callback: (...args: LH.CrdpEvents[TEvent]) => void): void;
      once<TEvent extends keyof LH.CrdpEvents>(event: TEvent, callback: (...args: LH.CrdpEvents[TEvent]) => void): void;
      off<TEvent extends keyof LH.CrdpEvents>(event: TEvent, callback: (...args: LH.CrdpEvents[TEvent]) => void): void;
      sendCommand<TMethod extends keyof LH.CrdpCommands>(method: TMethod, ...params: LH.CrdpCommands[TMethod]['paramsType']): Promise<LH.CrdpCommands[TMethod]['returnType']>;
    }

    /** The limited driver interface shared between pre and post Fraggle Rock Lighthouse. */
    export interface FRTransitionalDriver {
      defaultSession: FRProtocolSession;
      evaluateAsync(expression: string, options?: {useIsolation?: boolean}): Promise<any>;
      evaluate<T extends any[], R>(mainFn: (...args: T) => R, options: {args: T, useIsolation?: boolean, deps?: Array<Function|string>}): FlattenedPromise<R>;
    }

    /** The limited context interface shared between pre and post Fraggle Rock Lighthouse. */
    export interface FRTransitionalContext {
      gatherMode: GatherMode
      driver: FRTransitionalDriver;
    }

    export interface PassContext {
      gatherMode: 'navigation';
      /** The url of the currently loaded page. If the main document redirects, this will be updated to keep track. */
      url: string;
      driver: Driver;
      passConfig: Config.Pass
      settings: Config.Settings;
      /** Gatherers can push to this array to add top-level warnings to the LHR. */
      LighthouseRunWarnings: Array<string | IcuMessage>;
      baseArtifacts: BaseArtifacts;
    }

    export interface LoadData {
      networkRecords: Array<Artifacts.NetworkRequest>;
      devtoolsLog: DevtoolsLog;
      trace?: Trace;
    }

    type PhaseResult_ = void|LH.GathererArtifacts[keyof LH.GathererArtifacts]
    export type PhaseResult = PhaseResult_ | Promise<PhaseResult_>

    export type GatherMode = 'snapshot'|'timespan'|'navigation';

    export interface GathererMeta {
      supportedModes: Array<GatherMode>;
    }

    export interface GathererInstance {
      name: keyof LH.GathererArtifacts;
      beforePass(context: LH.Gatherer.PassContext): PhaseResult;
      pass(context: LH.Gatherer.PassContext): PhaseResult;
      afterPass(context: LH.Gatherer.PassContext, loadData: LH.Gatherer.LoadData): PhaseResult;
    }

    export interface FRGathererInstance {
      name: keyof LH.GathererArtifacts; // temporary COMPAT measure until artifact config support is available
      meta: GathererMeta;
      snapshot(context: FRTransitionalContext): PhaseResult;
    }

    namespace Simulation {
      export type GraphNode = import('../lighthouse-core/lib/dependency-graph/base-node').Node;
      export type GraphNetworkNode = _NetworkNode;
      export type GraphCPUNode = _CPUNode;
      export type Simulator = _Simulator;

      export interface MetricCoefficients {
        intercept: number;
        optimistic: number;
        pessimistic: number;
      }

      export interface Options {
        rtt?: number;
        throughput?: number;
        maximumConcurrentRequests?: number;
        cpuSlowdownMultiplier?: number;
        layoutTaskMultiplier?: number;
        additionalRttByOrigin?: Map<string, number>;
        serverResponseTimeByOrigin?: Map<string, number>;
      }

      export interface NodeTiming {
        startTime: number;
        endTime: number;
        duration: number;
      }

      export interface Result {
        timeInMs: number;
        nodeTimings: Map<GraphNode, NodeTiming>;
      }
    }
  }
}

// empty export to keep file a module
export {};
