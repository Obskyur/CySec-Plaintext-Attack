import asyncio
import aiohttp
import os
from dataclasses import dataclass
from typing import Dict, Optional, Any
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

@dataclass
class URLs:
    local: str = "http://localhost:5000/"
    aws: str = "http://34.212.126.162/"
    current: str = local

@dataclass
class Credentials:
    username: str = os.getenv('STUDENT_USERNAME')
    password: str = os.getenv('STUDENT_PASSWORD')

@dataclass
class Messages:
    m0: str = "0" * 64
    m1: str = "0" * 63 + "1"

class CryptoAPI:
    def __init__(self, base_url: str = URLs.current):
        self.base_url = base_url
        self.credentials = Credentials()
        self.messages = Messages()

    async def _make_request(
        self, 
        session: aiohttp.ClientSession, 
        endpoint: str, 
        method: str = "POST", 
        **kwargs
    ) -> Optional[Dict]:
        url = f"{self.base_url}/{endpoint}"
        try:
            async with session.request(method, url, **kwargs) as response:
                return await response.json()
        except Exception as e:
            print(f"Request failed for {endpoint}: {e}")
            return None

    async def encrypt_message(
        self, 
        session: aiohttp.ClientSession, 
        message: str
    ) -> Optional[Dict]:
        data = {
            "username": self.credentials.username,
            "password": self.credentials.password,
            "message": message
        }
        return await self._make_request(session, "encrypt", json=data)

    async def submit_challenge(
        self, 
        session: aiohttp.ClientSession
    ) -> Optional[Dict]:
        data = {
            "username": self.credentials.username,
            "password": self.credentials.password,
            "m0": self.messages.m0,
            "m1": self.messages.m1
        }
        return await self._make_request(session, "challenge", json=data)

    async def submit_guess(
        self, 
        session: aiohttp.ClientSession, 
        challenge_id: str, 
        guess: int
    ) -> Optional[Dict]:
        data = {
            "username": self.credentials.username,
            "password": self.credentials.password,
            "challenge_id": challenge_id,
            "b_prime": guess
        }
        return await self._make_request(session, "guess", json=data)

class PadCollector:
    def __init__(self, api: CryptoAPI, required_pads: int = 32):
        self.api = api
        self.required_pads = required_pads

    async def collect_pads(self, session: aiohttp.ClientSession) -> Dict[str, str]:
        pads = {}
        while len(pads) < self.required_pads:
            new_pads = await self._request_batch(session, self.required_pads * 2 - len(pads))
            pads.update(new_pads)
            if len(pads) < self.required_pads:
                await asyncio.sleep(0.1)
        return pads

    async def _request_batch(
        self, 
        session: aiohttp.ClientSession, 
        count: int
    ) -> Dict[str, str]:
        tasks = [
            self.api.encrypt_message(session, self.api.messages.m0) 
            for _ in range(count)
        ]
        responses = await asyncio.gather(*tasks)
        return {
            res['r']: res['c2'] 
            for res in responses 
            if res and 'r' in res and 'c2' in res
        }

class ChallengeResolver:
    def __init__(self, api: CryptoAPI):
        self.api = api
        self.pad_collector = PadCollector(api)
        
    def determine_message(self, challenge: Dict[str, Any], pads: Dict[str, str]) -> int:
        return 0 if pads[challenge['r']] == challenge['c2'] else 1

    async def solve_challenges(self, target_score: int = 100, max_attempts: int = 500):
        result = {"new_score": 0}
        attempts = 0

        async with aiohttp.ClientSession() as session:
            while result['new_score'] < target_score and attempts < max_attempts:
                result = await self._attempt_challenge(session)
                attempts += 1
                print(f"Result: {result}")

            self._print_final_result(result['new_score'], attempts, target_score)

    async def _attempt_challenge(self, session: aiohttp.ClientSession) -> Dict:
        pads = await self.pad_collector.collect_pads(session)
        if len(pads) < self.pad_collector.required_pads:
            return {"new_score": 0}

        challenge = await self.api.submit_challenge(session)
        if not challenge:
            return {"new_score": 0}

        guess = self.determine_message(challenge, pads)
        result = await self.api.submit_guess(session, challenge['challenge_id'], guess)
        return result or {"new_score": 0}

    def _print_final_result(self, score: int, attempts: int, target: int):
        if score >= target:
            print("Success!")
        else:
            print(f"Failed to reach score {target} after {attempts} attempts")

async def main():
    api = CryptoAPI()
    resolver = ChallengeResolver(api)
    await resolver.solve_challenges()

if __name__ == "__main__":
    asyncio.run(main())